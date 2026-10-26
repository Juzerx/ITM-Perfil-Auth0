
require('dotenv').config();

const express = require('express');
const { auth, requiresAuth } = require('express-openid-connect');

const app = express();

app.use(express.urlencoded({ extended: false }));

app.use(
  auth({
    issuerBaseURL: process.env.AUTH0_ISSUER_BASE_URL,
    baseURL: process.env.BASE_URL,
    clientID: process.env.AUTH0_CLIENT_ID,
    secret: process.env.SESSION_SECRET,
    authRequired: false,
    auth0Logout: true
  })
);

function escapeHtml(value) {
  return String(value ?? '').replace(/[&<>"']/g, char => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[char]);
}

// Obtiene un token de acceso para Management API.
// Esta función se ejecuta únicamente en el servidor.
async function getManagementToken() {
  const domain = process.env.AUTH0_ISSUER_BASE_URL.replace(/\/$/, '');

  const response = await fetch(`${domain}/oauth/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      client_id: process.env.AUTH0_MGMT_CLIENT_ID,
      client_secret: process.env.AUTH0_MGMT_CLIENT_SECRET,
      audience: `${domain}/api/v2/`,
      grant_type: 'client_credentials'
    })
  });

  const data = await response.json();

  if (!response.ok) {
    throw new Error(`No se pudo obtener el token: ${response.status}`);
  }

  return data.access_token;
}

// Consulta el perfil de Auth0 y sus metadatos.
async function getAuth0Profile(userId) {
  const domain = process.env.AUTH0_ISSUER_BASE_URL.replace(/\/$/, '');
  const token = await getManagementToken();

  const response = await fetch(
    `${domain}/api/v2/users/${encodeURIComponent(userId)}`,
    {
      headers: { Authorization: `Bearer ${token}` }
    }
  );

  const data = await response.json();

  if (!response.ok) {
    throw new Error(`No se pudo leer el perfil: ${response.status}`);
  }

  return data;
}

app.get('/', (req, res) => {
  if (!req.oidc.isAuthenticated()) {
    return res.send(`
      <h1>ITM Perfil</h1>
      <p>Aplicación de gestión de datos personales.</p>
      <a href="/login">Iniciar sesión con Auth0</a>
    `);
  }

  res.send(`
    <h1>ITM Perfil</h1>
    <p>Bienvenido, ${escapeHtml(req.oidc.user.name || 'usuario')}.</p>
    <a href="/perfil">Modificar mis datos</a>
    <br><br>
    <a href="/logout">Cerrar sesión</a>
  `);
});

// ACTIVIDAD 3: mostrar el formulario precargado.
app.get('/perfil', requiresAuth(), async (req, res) => {
  try {
    const profile = await getAuth0Profile(req.oidc.user.sub);
    const metadata = profile.user_metadata || {};

    const tipo = metadata.tipoDocumento || '';
    const numero = metadata.numeroDocumento || '';
    const direccion = metadata.direccion || '';
    const telefono = metadata.telefono || '';

    res.send(`
      <!DOCTYPE html>
      <html lang="es">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Mi perfil - ITM</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 40px auto;
            padding: 20px;
            background: #dadada;
            color: #020f2c;
          }
          form {
            background: white;
            padding: 24px;
            border-radius: 12px;
          }
          label { display: block; margin-top: 16px; }
          input, select {
            width: 100%;
            box-sizing: border-box;
            padding: 10px;
            margin-top: 6px;
          }
          button {
            margin-top: 22px;
            padding: 12px 20px;
            color: #ffffff;
            background: #031d5c;
            border: 0;
            cursor: pointer;
          }
        </style>
      </head>
      <body>
        <h1>Mis datos personales</h1>
        <p>Actualiza la información de tu perfil.</p>

        <form action="/perfil" method="POST">
          <label for="tipoDocumento">Tipo de documento</label>
          <select id="tipoDocumento" name="tipoDocumento" required>
            <option value="">Selecciona una opción</option>
            <option value="CC" ${tipo === 'CC' ? 'selected' : ''}>Cédula de ciudadanía</option>
            <option value="CE" ${tipo === 'CE' ? 'selected' : ''}>Cédula de extranjería</option>
            <option value="TI" ${tipo === 'TI' ? 'selected' : ''}>Tarjeta de identidad</option>
            <option value="Pasaporte" ${tipo === 'Pasaporte' ? 'selected' : ''}>Pasaporte</option>
          </select>

          <label for="numeroDocumento">Número de documento</label>
          <input id="numeroDocumento" name="numeroDocumento"
            value="${escapeHtml(numero)}" maxlength="30" required>

          <label for="direccion">Dirección</label>
          <input id="direccion" name="direccion"
            value="${escapeHtml(direccion)}" maxlength="150" required>

          <label for="telefono">Teléfono</label>
          <input id="telefono" name="telefono" type="tel"
            value="${escapeHtml(telefono)}" maxlength="30" required>

          <button type="submit">Guardar cambios</button>
        </form>

        <p><a href="/">Volver al inicio</a></p>
      </body>
      </html>
    `);
  } catch (error) {
    console.error('Error consultando el perfil:', error.message);
    res.status(500).send(
      'No fue posible cargar el perfil. Revisa la configuración de Auth0.'
    );
  }
});

// ACTIVIDAD 4: guardar los datos en user_metadata.
app.post('/perfil', requiresAuth(), async (req, res) => {
  const { tipoDocumento, numeroDocumento, direccion, telefono } = req.body;

  const tiposPermitidos = ['CC', 'CE', 'TI', 'Pasaporte'];

  if (
    !tiposPermitidos.includes(tipoDocumento) ||
    typeof numeroDocumento !== 'string' ||
    typeof direccion !== 'string' ||
    typeof telefono !== 'string' ||
    !numeroDocumento.trim() ||
    !direccion.trim() ||
    !telefono.trim() ||
    numeroDocumento.length > 30 ||
    direccion.length > 150 ||
    telefono.length > 30
  ) {
    return res.status(400).send('Los datos enviados no son válidos.');
  }

  try {
    const domain = process.env.AUTH0_ISSUER_BASE_URL.replace(/\/$/, '');
    const token = await getManagementToken();
    const userId = req.oidc.user.sub;

    const response = await fetch(
      `${domain}/api/v2/users/${encodeURIComponent(userId)}`,
      {
        method: 'PATCH',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          user_metadata: {
            tipoDocumento,
            numeroDocumento: numeroDocumento.trim(),
            direccion: direccion.trim(),
            telefono: telefono.trim()
          }
        })
      }
    );

    if (!response.ok) {
      const detail = await response.text();
      console.error('Error de Management API:', response.status, detail);
      return res.status(502).send(
        'Auth0 no pudo guardar los cambios. Revisa los permisos de la API.'
      );
    }

    res.send(`
      <h1>Datos actualizados correctamente</h1>
      <p>La información se guardó en user_metadata de Auth0.</p>
      <a href="/perfil">Volver al perfil</a>
      <br><br>
      <a href="/">Inicio</a>
    `);
  } catch (error) {
    console.error('Error guardando el perfil:', error.message);
    res.status(500).send('Ocurrió un error al actualizar los datos.');
  }
});

const port = process.env.PORT || 3000;

app.listen(port, () => {
  console.log(`ITM Perfil disponible en http://localhost:${port}`);
});
