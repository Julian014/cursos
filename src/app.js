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

      res.render("admin/crear_usuario_admin.hbs", {
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

      res.render("admin/crear_usuario_cursos.hbs", {
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
          saldo_pendiente
        FROM pagos_cursos
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


  
  


app.get('/', (req, res) => {
    res.redirect('/login');
});

app.listen(3000, () => {
    console.log('Servidor corriendo en el puerto 3000');
});
