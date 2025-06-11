const express = require('express');
const session = require('express-session');
const hbs = require('hbs');
const pool = require('./db'); // Importamos la configuración de la base de datos
const path = require('path');
const moment = require('moment');
const fs = require('fs');
const cron = require('node-cron');

const app = express();
const fileUpload = require('express-fileupload');
const jwt = require('jsonwebtoken'); // Importa jsonwebtoken
const SECRET_KEY = 'MiClaveSuperSegura!$%&/()=12345';
const admin = require('firebase-admin');

app.use(session({
    secret: 'mysecret',  // Cambia este secreto
    resave: false,
    saveUninitialized: true
}));

// Configurar el motor de plantillas
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));  // Asegúrate de que apunte correctamente a tu carpeta de vistas
app.use(express.static(__dirname + '/public'));

// Middleware para parsing
app.use(express.urlencoded({ extended: false }));


// Ruta para mostrar el formulario de login
app.get('/login', (req, res) => {
    res.render('login/login');
});

// Asegúrate de que Express pueda manejar datos en formato JSON
app.use(express.json());



hbs.registerHelper('formatDate', (date) => {
    return moment(date).format('DD/MM/YYYY');
});


// Registrar el helper 'eq' para comparar dos valores
hbs.registerHelper('eq', (a, b) => {
    return a === b;
});

app.use(express.static('public', {
    etag: false,
    maxAge: 0
  }));
  

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

hbs.registerHelper('formatearFecha', function (fecha) {
  if (!(fecha instanceof Date)) {
    fecha = new Date(fecha);
  }

  if (isNaN(fecha)) return 'Fecha inválida';

  const dia = String(fecha.getDate()).padStart(2, '0');
  const mes = String(fecha.getMonth() + 1).padStart(2, '0');
  const anio = fecha.getFullYear();

  return `${dia}/${mes}/${anio}`;
});
// Ruta para manejar el login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        // Consulta para verificar si el usuario existe con el correo, contraseña dados y está activo
        const [results] = await pool.query(
            'SELECT * FROM usuarios WHERE email = ? AND password = ?',
            [email, password]
        );

        if (results.length > 0) {
            const user = results[0];

            // Verificar si el estado del usuario es activo
            if (user.estado !== 'activo') {
                // Devolver un mensaje de usuario inactivo sin destruir la sesión
                return res.json({ status: 'inactive', message: 'Usuario inactivo' });
            } else {
                // Almacena los datos del usuario en la sesión
                req.session.user = user;  // Almacena el objeto completo del usuario
                req.session.userId = user.id; // Guarda el `userId` en la sesión
                req.session.name = user.nombre;  // Guarda el nombre del usuario en la sesión
                req.session.loggedin = true;  // Establece el estado de sesión como conectado
                req.session.roles = user.role;  // Guarda los roles en la sesión
                req.session.cargo = user.cargo; // Almacena el cargo en la sesión

                const role = user.role;  // Obtiene el rol del usuario

                // Redirige basado en el rol del usuario
                if (role === 'admin') {
                    return res.redirect('/menuAdministrativo');
                } else if (role === 'tecnico') {
                    return res.redirect('/tecnico');
                } else if (role === 'residentes') {
                    return res.redirect('/menu_residentes');
                }
            }
        } else {
            // Muestra la página de login con mensaje de error si las credenciales son incorrectas
            res.render('login/login', { error: 'Correo, contraseña incorrectos o usuario inactivo' });
        }
    } catch (err) {
        // Maneja los errores y envía una respuesta 500 en caso de problemas con la base de datos o el servidor
        res.status(500).json({ error: err.message });
    }
});



// Verifica que el código se ejecuta en el navegador antes de registrar el Service Worker
if (typeof window !== "undefined" && "serviceWorker" in navigator) {
    window.addEventListener("load", () => {
      navigator.serviceWorker.register("/service-worker.js")
        .then((registration) => {
          console.log("✅ Service Worker registrado correctamente:", registration);
        })
        .catch((error) => console.error("❌ Error al registrar el Service Worker:", error));
    });
  
    // Recargar la página cuando se active un nuevo SW
    navigator.serviceWorker.addEventListener("controllerchange", () => {
      console.log("♻️ Nueva versión activa, recargando página...");
      window.location.reload();
    });
  }
  







// Ruta para el menú administrativo
app.get('/geolocalizacion', (req, res) => {
    if (req.session.loggedin === true) {
        const userId = req.session.userId;

        const nombreUsuario = req.session.user.name; // Use user session data
        res.render('administrativo/mapa/ver_mapa.hbs', { nombreUsuario ,userId });
    } else {
        res.redirect('/login');
    }
});



// Ruta para mostrar la página de restablecimiento de contraseña
app.get('/reset-password', (req, res) => {
    res.render('login/reset-password');
});



const formatDateForMySQL = (date) => {
    return date.toISOString().slice(0, 19).replace('T', ' ');
};

// ✅ Ruta para solicitar restablecimiento de contraseña
app.post('/request-password-reset', async (req, res) => {
    try {
        const { email } = req.body;

        // Verificar si el usuario existe
        const [users] = await pool.query(
            'SELECT reset_token, reset_token_exp FROM usuarios WHERE email = ?',
            [email]
        );

        let token;
        let expireTime = new Date(Date.now() + 3600000); // Sumar 1 hora en UTC
        let mysqlExpireTime = formatDateForMySQL(expireTime);

        if (users.length > 0 && users[0].reset_token && new Date(users[0].reset_token_exp) > new Date()) {
            // Si el usuario ya tiene un token válido, reutilizarlo
            token = users[0].reset_token;
            mysqlExpireTime = users[0].reset_token_exp; // Mantener la fecha de expiración original
        } else {
            // Generar un nuevo token y actualizar en la base de datos
            token = crypto.randomBytes(32).toString('hex');
            const [result] = await pool.query(
                'UPDATE usuarios SET reset_token = ?, reset_token_exp = ? WHERE email = ?',
                [token, mysqlExpireTime, email]
            );

            if (result.affectedRows === 0) {
                return res.status(400).json({ message: 'No se pudo actualizar el token, verifica el correo.' });
            }
        }

        console.log("✅ Token generado:", token);
        console.log("✅ Fecha de expiración guardada:", mysqlExpireTime);

        // Verificar que el token realmente se guardó en la base de datos
        const [checkToken] = await pool.query(
            'SELECT reset_token, reset_token_exp FROM usuarios WHERE email = ?', 
            [email]
        );
        console.log("🔍 Token en la BD después de la actualización:", checkToken[0]?.reset_token);
        console.log("🔍 Expiración en la BD:", checkToken[0]?.reset_token_exp);

        // Construir enlace de restablecimiento
        const resetLink = `http://sistemacerceta.com/reset-password/${encodeURIComponent(token)}`;

        // Configuración del correo
        const transporter = nodemailer.createTransport({
            service: 'Gmail',
            auth: {
        user: 'cercetasolucionempresarial@gmail.com', // ← Faltaba cerrar comillas aquí
                pass: 'yuumpbszqtbxscsq'
            }
        });

        // Enviar el correo con el enlace
        await transporter.sendMail({
            from: 'cercetasolucionempresarial@gmail.com',
            to: email,
            subject: `Restablece tu contraseña`,
            html: `<p>Haz clic en el siguiente enlace para restablecer tu contraseña:</p>
                   <a href="${resetLink}">${resetLink}</a>`
        });

        res.json({ message: 'Se ha enviado un enlace a tu correo.' });

    } catch (error) {
        console.error("❌ Error en /request-password-reset:", error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});

// ✅ Ruta para validar el token y mostrar el formulario de restablecimiento
app.get('/reset-password/:token', async (req, res) => {
    try {
        const { token } = req.params;
        console.log("🔑 Token recibido en la URL:", token);

        // Verificar si el token es válido y no ha expirado
        const [users] = await pool.query(
            'SELECT id FROM usuarios WHERE reset_token = ? AND CONVERT_TZ(reset_token_exp, "+00:00", "+00:00") > UTC_TIMESTAMP()', 
            [token]
        );
        
        console.log("🔎 Resultado de la consulta:", users);

        if (!users || users.length === 0) {
            return res.send("⚠️ El enlace para restablecer la contraseña es inválido o ha expirado.");
        }

        res.render('login/change-password.hbs', { token });

    } catch (error) {
        console.error("❌ Error en /reset-password/:token:", error);
        res.status(500).send("Error en el servidor.");
    }
});






app.post('/update-password', async (req, res) => {
    try {
        const { token, password, confirmPassword } = req.body;

        if (password !== confirmPassword) {
            return res.status(400).json({ message: 'Las contraseñas no coinciden.' });
        }

        if (password.length < 8) {
            return res.status(400).json({ message: 'La contraseña debe tener al menos 8 caracteres.' });
        }

        const [users] = await pool.query(
            'SELECT id, reset_token_exp FROM usuarios WHERE reset_token = ? AND reset_token_exp > UTC_TIMESTAMP()', 
            [token]
        );

        if (users.length === 0) {
            return res.status(400).json({ message: 'El enlace para restablecer la contraseña es inválido o ha expirado.' });
        }

        const userId = users[0].id;

        await pool.query(
            'UPDATE usuarios SET password = ?, reset_token = NULL, reset_token_exp = NULL WHERE id = ?', 
            [password, userId]
        );

        res.json({ message: "Contraseña actualizada con éxito.", redirect: "/login" });

    } catch (error) {
        console.error("❌ Error en /update-password:", error);
        res.status(500).json({ message: 'Error en el servidor' });
    }
});



app.get('/menu_residentes', async (req, res) => {
    if (req.session.loggedin === true) {
        const name = req.session.name;
        const userId = req.session.userId;

        try {
            // Consulta para obtener el edificio_id del usuario
            const [userResult] = await pool.query('SELECT edificio FROM usuarios WHERE id = ?', [userId]);
            if (userResult.length === 0) {
                return res.status(404).send('Usuario no encontrado');
            }
            
            const edificioId = userResult[0].edificio;
            console.log("Edificio ID del usuario:", edificioId);

            // Consulta para obtener las publicaciones del edificio
            const [resultados] = await pool.query('SELECT * FROM publicaciones WHERE edificio_id = ? ORDER BY fecha DESC', [edificioId]);
            console.log("Resultados de publicaciones:", resultados);

            // Convertir los datos binarios a base64
            const blogPosts = resultados.map((post) => ({
                ...post,
                imagen: post.imagen ? post.imagen.toString('base64') : null,
                pdf: post.pdf ? post.pdf.toString('base64') : null,
                word: post.word ? post.word.toString('base64') : null,
                excel: post.excel ? post.excel.toString('base64') : null
            }));

            res.render('Residentes/home_residentes.hbs', { name, userId, blogPosts, layout: 'layouts/nav_residentes.hbs' });
        } catch (err) {
            console.error(err);
            res.status(500).send('Error al obtener las entradas del blog');
        }
    } else {
        res.redirect('/login');
    }
});












// En tu configuración de Handlebars
hbs.registerHelper('ifCond', function (v1, v2, options) {
    return (v1 === v2) ? options.fn(this) : options.inverse(this);
});





app.get('/subir_pago_residentes', async (req, res) => {
    if (req.session.loggedin === true) {
        const userId = req.session.userId;

        try {
            // Consulta para obtener edificio y apartamento del usuario
            const query = 'SELECT edificio, apartamento FROM usuarios WHERE id = ?';
            const [rows] = await pool.query(query, [userId]);

            if (rows.length > 0) {
                const { edificio, apartamento } = rows[0];
                console.log('Edificio:', edificio, 'Apartamento:', apartamento); // Verifica los valores obtenidos
                
                // Pasa solo el edificio y apartamento específicos
                res.render('Residentes/pagos/subir_mi_pago.hbs', { 
                    nombreUsuario: req.session.user.name, 
                    userId, 
                    edificioSeleccionado: edificio, 
                    layout: 'layouts/nav_residentes.hbs',
                    apartamentoSeleccionado: apartamento
                });
            } else {
                res.redirect('/login'); // Redirige si no se encuentra el usuario
            }
        } catch (error) {
            console.error('Error al obtener edificio y apartamento:', error);
            res.status(500).send('Error interno del servidor');
        }
    } else {
        res.redirect('/login');
    }
});



























// Ruta para manejar el cierre de sesión
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({ error: 'Error al cerrar sesión' });
        }
        res.redirect('/login');  // Redirige al usuario a la página de login
    });
});






const nodemailer = require('nodemailer');
const { v4: uuidv4 } = require('uuid'); // Utiliza UUID para generar IDs únicos

// Configurar el transporter con nodemailer
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
         user: 'amayacarlos898@gmail.com', // ← Faltaba cerrar comillas aquí
                pass: 'zfqccwbvwzgccdmj'
    },
    messageId: uuidv4(), // Genera un Message-ID único para cada correo enviado
});

const crypto = require('crypto'); // Importa el módulo crypto



hbs.registerHelper('json', function(context) {
    return JSON.stringify(context);
});






app.get("/menuAdministrativo", async (req, res) => {
    if (req.session.loggedin === true) {
        try {
            const userId = req.session.userId;

            const nombreUsuario = req.session.name || req.session.user.name;
            console.log(`El usuario ${nombreUsuario} está autenticado.`);
            req.session.nombreGuardado = nombreUsuario;

            // Obtén el cargo del usuario desde la sesión y conviértelo en un array
            const cargos = req.session.cargo.split(',').map(cargo => cargo.trim());
            console.log(`Cargos del usuario: ${cargos}`);

            // Define las variables de cargo en función de si están en el array
            const esGerente = cargos.includes('Gerente');
            const esAdministracionOperativa = cargos.includes('administracion_operativa');
            const esContabilidad = cargos.includes('contabilidad');
            const esOperativo = cargos.includes('operativo');

            // Muestra en consola para verificar que los valores son correctos
            console.log({ esGerente, esAdministracionOperativa, esContabilidad, esOperativo });

            // Consulta para contar los residentes con rol "clientes"
            const [clientesRows] = await pool.query('SELECT COUNT(*) AS totalClientes FROM usuarios WHERE role = "clientes"');
            const totalClientes = clientesRows[0].totalClientes;

            // Consulta para contar la cantidad de apartamentos
            const [apartamentosRows] = await pool.query('SELECT COUNT(*) AS totalApartamentos FROM apartamentos');
            const totalApartamentos = apartamentosRows[0].totalApartamentos;

            // Consulta para contar la cantidad de edificios
            const [edificiosRows] = await pool.query('SELECT COUNT(*) AS totaledificios FROM edificios');
            const totaledificios = edificiosRows[0].totaledificios;

            // Consulta para contar la cantidad de empleados
            const [empleadosRows] = await pool.query('SELECT COUNT(*) AS totalEmpleados FROM usuarios WHERE role = "admin"');
            const totalEmpleados = empleadosRows[0].totalEmpleados;

            // Consulta para contar la cantidad de residentes
            const [residentesRows] = await pool.query('SELECT COUNT(*) AS totalResidentes FROM usuarios WHERE role = "residentes"');
            const residentes = residentesRows[0].totalResidentes;

            // Nueva consulta para obtener las últimas alertas con nombre_actividad y fecha_ejecucion
            const [alertasRows] = await pool.query('SELECT nombre_actividad, fecha_ejecucion FROM alertas ORDER BY fecha_ejecucion DESC LIMIT 5');
            const alertas = alertasRows;

            // Consulta para obtener los pagos mensuales por edificio
            const [pagosMensualesRows] = await pool.query(`
                SELECT 
                    nombre_edificio, 
                    MONTH(fecha_pago) AS mes, 
                    SUM(valor_pago) AS total_mensual 
                FROM pagos_apartamentos 
                GROUP BY nombre_edificio, MONTH(fecha_pago)
                ORDER BY nombre_edificio, mes
            `);

            // Transformar los datos para el gráfico
            const datosGrafico = {};
            pagosMensualesRows.forEach(row => {
                if (!datosGrafico[row.nombre_edificio]) {
                    datosGrafico[row.nombre_edificio] = Array(12).fill(0);
                }
                datosGrafico[row.nombre_edificio][row.mes - 1] = row.total_mensual;
            });
// Nueva consulta para obtener los últimos cinco pagos
const [ultimosPagosRows] = await pool.query(`
    SELECT apartamento_id, fecha_pago, valor_pago 
    FROM pagos_apartamentos 
    ORDER BY fecha_pago DESC 
    LIMIT 5
`);
const ultimosPagos = ultimosPagosRows;

            // Renderiza la vista y pasa los datos necesarios
            res.render("administrativo/menuadministrativo.hbs", {
                layout: 'layouts/nav_admin.hbs',
                name: nombreUsuario,
                esGerente,
                esAdministracionOperativa,
                esContabilidad,
                esOperativo,
                userId,
                totalClientes,
                totalApartamentos,
                totaledificios,
                totalEmpleados,  // Pasamos la variable totalEmpleados a la vista
                residentes,       // Pasamos la variable totalResidentes como residentes a la vista
                ultimosPagos,  // Pasamos los últimos pagos a la vista

                alertas,          // Pasamos las últimas alertas a la vista
                datosGrafico: JSON.stringify(datosGrafico)  // Convertir datosGrafico a JSON
            });
        } catch (error) {
            console.error('Error al obtener el conteo de datos:', error);
            res.status(500).send('Error al cargar el menú administrativo');
        }
    } else {
        res.redirect("/login");
    }
});













app.post('/login/admin', async (req, res) => {
  const { email, password } = req.body;

  try {
    const [rows] = await pool.query(
      'SELECT * FROM usuarios_administradores WHERE email = ? AND password = ?',
      [email, password]
    );

    if (rows.length === 0) {
      return res.status(401).send('Correo o contraseña incorrecta');
    }

    const user = rows[0];

    // Guardamos en sesión
    req.session.loggedin = true;
    req.session.userId = user.id;
    req.session.name = user.nombre || user.email;

    // Redirige al menú admin
    res.redirect('/menu_admin');
  } catch (error) {
    console.error('Error en /login/admin:', error);
    res.status(500).send('Error interno del servidor');
  }
});



app.get("/menu_admin", async (req, res) => {
  if (req.session.loggedin === true) {
    try {
      const userId = req.session.userId;
      const nombreUsuario = req.session.name;
      console.log(`El usuario ${nombreUsuario} está autenticado.`);
      req.session.nombreGuardado = nombreUsuario;

      res.render("admin/home.hbs", {
        layout: 'layouts/nav_admin.hbs',
        name: nombreUsuario,
        userId,
      });
    } catch (error) {
      console.error('Error al obtener el conteo de datos:', error);
      res.status(500).send('Error al cargar el menú administrativo');
    }
  } else {
    res.redirect("/login");
  }
});








app.get("/usuarios_admin", async (req, res) => {
  if (req.session.loggedin === true) {
    try {
      const userId = req.session.userId;
      const nombreUsuario = req.session.name;
      console.log(`El usuario ${nombreUsuario} está autenticado.`);
      req.session.nombreGuardado = nombreUsuario;

      // Consulta para traer todos los administradores
      const [usuariosAdmin] = await pool.query(`
        SELECT id, email, nombre, rol, creado_en 
        FROM usuarios_administradores
        ORDER BY creado_en DESC
      `);

      res.render("admin/crear_usuario_admin.hbs", {
        layout: 'layouts/nav_admin.hbs',
        name: nombreUsuario,
        userId,
        usuariosAdmin
      });
    } catch (error) {
      console.error('Error al obtener los administradores:', error);
      res.status(500).send('Error al cargar el menú administrativo');
    }
  } else {
    res.redirect("/login");
  }
});

app.get("/menu_cursos", async (req, res) => {
    if (req.session.loggedin === true) {
        try {
            const userId = req.session.userId;
            const nombreUsuario = req.session.name || req.session.user.name;
            console.log(`El usuario ${nombreUsuario} está autenticado.`);
            req.session.nombreGuardado = nombreUsuario;

            // Renderiza la vista y pasa los datos necesarios
            res.render("cursos/home.hbs", {
                layout: 'nav_cursos',
                name: nombreUsuario,
                userId,
            });
        } catch (error) {
            console.error('Error al obtener el conteo de datos:', error);
            res.status(500).send('Error al cargar el menú administrativo');
        }
    } else {
        res.redirect("/login");
    }
});



// Ruta POST
app.post('/guardar_usuario_admin', async (req, res) => {
  console.log('POST /guardar_usuario_admin llamado');
  console.log('Req.body:', req.body);

  const { nombre, email, rol } = req.body;
  if (!nombre || !email || !rol) {
    console.log('Validación fallida: faltan campos');
    return res.status(400).render('crear_usuario_admin', {
      error: 'Todos los campos son obligatorios',
      form: { nombre, email }
    });
  }
  console.log('Validación exitosa');

  // 1) Generar contraseña aleatoria
  const rawPassword = crypto.randomBytes(4).toString('hex');
  console.log('Contraseña generada (en claro):', rawPassword);

  // 2) Insertar en BD guardando la contraseña en claro
  const sql = `
    INSERT INTO usuarios_administradores
      (nombre, email, password, rol, creado_en)
    VALUES (?, ?, ?, ?, NOW())
  `;
  try {
    const [result] = await pool.query(sql, [nombre, email, rawPassword, rol]);
    console.log('Inserción exitosa, resultado:', result);

    // 3) Enviar correo con credenciales
    await transporter.sendMail({
      from: '"soporte Admin" <amayacarlos898@gmail.com>',
      to: email,
      subject: 'Tus credenciales de administrador',
      html: `
        <p>Hola <strong>${nombre}</strong>,</p>
        <p>Tu cuenta ha sido creada con éxito:</p>
        <ul>
          <li><strong>Email:</strong> ${email}</li>
          <li><strong>Contraseña:</strong> ${rawPassword}</li>
        </ul>
        <p>Por favor ingresa y cambia tu contraseña.</p>
      `
    });
    console.log('Correo enviado a:', email);

    // 4) Redirigir con éxito
    return res.redirect('/usuarios_admin?success=1');

  } catch (err) {
    console.error('Error al guardar el usuario o enviar correo:', err);
    if (err.code === 'ER_DUP_ENTRY') {
      console.log('Email duplicado detectado');
      return res.status(409).render('crear_usuario_admin', {
        error: 'El correo ya está registrado',
        form: { nombre, email }
      });
    }
    return res.status(500).render('crear_usuario_admin', {
      error: 'Error al crear el usuario',
      form: { nombre, email }
    });
  }
});



app.get("/usuarios_cursos", async (req, res) => {
  if (req.session.loggedin === true) {
    try {
      const userId = req.session.userId;
      const nombreUsuario = req.session.name;
      console.log(`El usuario ${nombreUsuario} está autenticado.`);
      req.session.nombreGuardado = nombreUsuario;

      // Hacer la consulta a la base de datos
      const [usuarios] = await pool.query(`
        SELECT id, nombre, correo, numero_documento, fecha_registro
        FROM usuarios_cursos
      `);

      res.render("admin/usuarios/cursos/consulta.hbs", {
        layout: 'layouts/nav_admin.hbs',
        name: nombreUsuario,
        userId,
        usuarios,
      });
    } catch (error) {
      console.error('Error al obtener los usuarios:', error);
      res.status(500).send('Error al cargar los usuarios');
    }
  } else {
    res.redirect("/login");
  }
});



app.get("/pagos_consulta", async (req, res) => {
  if (req.session.loggedin === true) {
    try {
      const userId = req.session.userId;
      const nombreUsuario = req.session.name;
      console.log(`El usuario ${nombreUsuario} está autenticado.`);
      req.session.nombreGuardado = nombreUsuario;

      // Ejecutamos la consulta sobre la tabla pagos_cursos
      const sql = `
        SELECT
          nombre,
          apellidos,
          correo,
          nombre_curso,
          total_curso,
          fecha_pago,
          saldo_pendiente,
          tipo_documento,
          numero_documento	
        FROM pagos
        ORDER BY fecha_pago DESC
      `;
      const [pagos] = await pool.query(sql);

      // Renderizamos la vista pasando el array de pagos
      res.render("admin/pagos/consulta.hbs", {
        layout: "layouts/nav_admin.hbs",
        name: nombreUsuario,
        userId,
        pagos
      });
    } catch (error) {
      console.error("Error al obtener pagos:", error);
      res.status(500).send("Error al cargar la consulta de pagos");
    }
  } else {
    res.redirect("/login");
  }
});



app.post('/pagos_nuevo', async (req, res) => {
  try {
    console.log('Datos recibidos:', req.body);

    // ✅ Reconstrucción de cursos si vienen como campos planos (ej: cursos[0][nombre_curso])
    let cursosReconstruidos = [];
    Object.keys(req.body).forEach(key => {
      const match = key.match(/^cursos\[(\d+)\]\[(\w+)\]$/);
      if (match) {
        const index = parseInt(match[1]);
        const campo = match[2];
        if (!cursosReconstruidos[index]) cursosReconstruidos[index] = {};
        cursosReconstruidos[index][campo] = req.body[key];
      }
    });

    if (cursosReconstruidos.length > 0) {
      req.body.cursos = cursosReconstruidos;
    }

    const { nombre, apellidos, correo, tipo_documento, numero_documento, cursos } = req.body;

    const camposRequeridos = ['nombre', 'apellidos', 'correo', 'tipo_documento', 'numero_documento', 'cursos'];
    const camposFaltantes = camposRequeridos.filter(campo => !req.body[campo]);

    if (camposFaltantes.length > 0) {
      return res.status(400).json({
        error: `Faltan los siguientes campos requeridos: ${camposFaltantes.join(', ')}`
      });
    }

    let cursosArray;
    if (Array.isArray(cursos)) {
      cursosArray = cursos;
    } else if (typeof cursos === 'object' && cursos !== null) {
      cursosArray = [cursos];
    } else {
      return res.status(400).json({
        error: 'Formato de cursos inválido. Debe ser un arreglo o un objeto.'
      });
    }

    for (const [i, curso] of cursosArray.entries()) {
      const camposCurso = ['nombre_curso', 'total_curso', 'abono', 'fecha_pago'];
      const faltantes = camposCurso.filter(campo => !curso[campo]);

      if (faltantes.length > 0) {
        return res.status(400).json({
          error: `Faltan los siguientes campos en el curso #${i + 1}: ${faltantes.join(', ')}`
        });
      }

      const { nombre_curso, total_curso, abono, fecha_pago } = curso;

      const total = parseFloat(total_curso);
      const abonoVal = parseFloat(abono);

      if (isNaN(total) || isNaN(abonoVal)) {
        return res.status(400).json({
          error: `Valores numéricos inválidos en el curso #${i + 1}`
        });
      }

      if (abonoVal > total) {
        return res.status(400).json({
          error: `El abono no puede ser mayor al total en el curso #${i + 1}`
        });
      }

      const saldo = total - abonoVal;

      try {
        await pool.query(
          `INSERT INTO pagos 
            (nombre, apellidos, correo, tipo_documento, numero_documento, nombre_curso, total_curso, abono, saldo_pendiente, fecha_pago)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
          [nombre, apellidos, correo, tipo_documento, numero_documento, nombre_curso, total, abonoVal, saldo, fecha_pago]
        );

      } catch (dbError) {
        console.error(`Error al guardar curso #${i + 1} en la base de datos:`, dbError);
        return res.status(500).json({ error: 'Error al guardar en la base de datos' });
      }
    }

    try {
      const [usuarioExistente] = await pool.query(
        'SELECT * FROM usuarios_cursos WHERE numero_documento = ?',
        [numero_documento]
      );

      if (usuarioExistente.length === 0) {
        const generarContrasena = () => {
          const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
          let pass = '';
          for (let i = 0; i < 8; i++) {
            pass += chars.charAt(Math.floor(Math.random() * chars.length));
          }
          return pass;
        };

        const contrasena = generarContrasena();

        await pool.query(
          `INSERT INTO usuarios_cursos (nombre, correo, numero_documento, contrasena)
           VALUES (?, ?, ?, ?)`,
          [`${nombre} ${apellidos}`, correo, numero_documento, contrasena]
        );

        console.log(`Usuario creado con documento ${numero_documento} y contraseña ${contrasena}`);

        // ✅ ENVÍO DE CORREO
        const transporter = nodemailer.createTransport({
          service: 'gmail',
          auth: {
      user: 'amayacarlos898@gmail.com', // ← Faltaba cerrar comillas aquí
                pass: 'zfqccwbvwzgccdmj'
          }
        });

        const mailOptions = {
          from: 'amayacarlos898@gmail.com',
          to: correo,
          subject: 'Acceso a la Plataforma',
        text: `Hola ${nombre},

¡Gracias por adquirir nuestros cursos y confiar en nuestra plataforma!

Te damos la bienvenida y te informamos que ya has sido registrado correctamente. A continuación, te compartimos tus credenciales de acceso:

Número de documento: ${numero_documento}  
Contraseña: ${contrasena}

Puedes ingresar a la plataforma con estos datos para acceder a todos los cursos que compraste y comenzar tu aprendizaje.

Te recomendamos guardar esta información en un lugar seguro.

¡Te deseamos mucho éxito en tu formación!

Saludos,  
El equipo de [Nombre de tu plataforma]`

        };

        transporter.sendMail(mailOptions, (error, info) => {
          if (error) {
            console.error('Error al enviar el correo:', error);
          } else {
            console.log('Correo enviado a', correo, info.response);
          }
        });
      }
    } catch (usuarioError) {
      console.error('Error al crear usuario en usuarios_cursos:', usuarioError);
      return res.status(500).json({ error: 'Error al crear usuario en usuarios_cursos' });
    }

    res.redirect('/pagos_consulta');

  } catch (error) {
    console.error('Error general del servidor:', error);
    res.status(500).json({ error: 'Error interno del servidor' });
  }
});







app.post("/eliminar_usuario_admin/:id", async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query("DELETE FROM usuarios_administradores WHERE id = ?", [id]);
    res.redirect("/usuarios_admin");
  } catch (error) {
    console.error("Error al eliminar usuario:", error);
    res.status(500).send("Error al eliminar el usuario");
  }
});

app.get("/editar_usuario_admin/:id", async (req, res) => {
  const id = req.params.id;
  try {
    const [rows] = await pool.query("SELECT * FROM usuarios_administradores WHERE id = ?", [id]);
    if (rows.length === 0) return res.status(404).send("Usuario no encontrado");

    res.render("admin/editar_usuario_admin.hbs", {
      layout: "layouts/nav_admin.hbs",
      usuario: rows[0],
    });
  } catch (error) {
    console.error("Error al obtener usuario:", error);
    res.status(500).send("Error al cargar usuario");
  }
});

app.get("/curso_desarrolloprofesional", async (req, res) => {
  if (req.session.loggedin === true) {
    try {
      const userId = req.session.userId;
      const nombreUsuario = req.session.name || req.session.user.name;
      const cursoRuta = "/curso_desarrolloprofesional";

      console.log(`🔐 El usuario ${nombreUsuario} está autenticado.`);

      // Verificar si ya aprobó el curso
      const [cursoAprobado] = await pool.query(
        'SELECT COUNT(*) AS total FROM cursosaprobados WHERE id_usuario = ? AND curso = ?',
        [userId, cursoRuta]
      );

      const aprobado = cursoAprobado[0].total > 0;

      res.render("cursos/contenidos/desarrolloprofesional/desarrolloprofesional", {
        layout: "layouts/nav_admin",
        name: nombreUsuario,
        userId,
        cursoAprobado: aprobado
      });

    } catch (error) {
      console.error('❌ Error al verificar curso aprobado:', error);
      res.status(500).send('Error al cargar la página del curso');
    }

  } else {
    res.redirect("/login");
  }
});



app.post('/registrar_curso_aprobado', async (req, res) => {
  try {
    const userId = req.session.userId;
    const { curso } = req.body;

    console.log('📥 Curso recibido:', curso);
    console.log('👤 Usuario de sesión:', userId);

    if (!userId || !curso) {
      console.warn('⚠️ Datos incompletos');
      return res.status(400).json({ error: 'Datos incompletos' });
    }

    // Verifica si ya existe el registro
    const [existente] = await pool.query(
      'SELECT * FROM cursosaprobados WHERE id_usuario = ? AND curso = ?',
      [userId, curso]
    );

    if (existente.length > 0) {
      console.log('⚠️ Curso ya registrado anteriormente.');
      return res.status(200).json({ mensaje: 'Curso ya estaba registrado previamente' });
    }

    // Si no existe, lo registra
    const [resultado] = await pool.query(
      'INSERT INTO cursosaprobados (id_usuario, curso, fecha_aprobacion) VALUES (?, ?, CONVERT_TZ(NOW(), "+00:00", "-05:00"))',
      [userId, curso]
    );

    console.log('✅ Curso registrado exitosamente:', resultado);
    res.status(200).json({ mensaje: 'Curso aprobado registrado con éxito' });

  } catch (err) {
    console.error('❌ Error registrando curso:', err);
    res.status(500).json({ error: 'Error del servidor' });
  }
});




app.get('/certificado', async (req, res) => {
  const userId = req.session.userId;
  const curso = req.query.curso;

  if (!userId || !curso) {
    return res.status(400).send('Faltan datos para generar el certificado');
  }

  try {
    const [result] = await pool.query(
      'SELECT fecha_aprobacion FROM cursosaprobados WHERE id_usuario = ? AND curso = ? ORDER BY fecha_aprobacion DESC LIMIT 1',
      [userId, curso]
    );

    if (!result || result.length === 0) {
      return res.status(404).send('No se encontró aprobación para este curso');
    }

    const fecha = new Date(result[0].fecha_aprobacion);

    res.render('cursos/contenidos/desarrolloprofesional/certificado', {
      usuario: req.session.name || 'Usuario',
      curso: curso.replace('/curso_', '').replace(/_/g, ' ').trim(),
      fecha: fecha.toLocaleDateString('es-CO', {
        day: 'numeric',
        month: 'long',
        year: 'numeric'
      })
    });

  } catch (error) {
    console.error('❌ Error al cargar certificado:', error);
    res.status(500).send('Error al generar el certificado');
  }
});


app.get('/', (req, res) => {
    res.redirect('/login');
});

app.listen(3000, () => {
    console.log('Servidor corriendo en el puerto 3000');
});
