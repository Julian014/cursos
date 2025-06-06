const mysql = require('mysql2');

// Crear la conexión a la base de datos
const pool = mysql.createPool({
    host: '147.93.118.246',
    user: 'root',
    password: '6mR5FNHf6cCODcny2CLCLU85UdGcyoUdGJGQBxD494nHKxQALYdMgyrKoIfB1du2',
    database: 'cursos',
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
}).promise();  // Esto convierte el pool en una versión que utiliza promesas

// Exportar la conexión para usarla en otros módulos
module.exports = pool;
