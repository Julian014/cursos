const bcrypt = require("bcrypt");

function login(req, res) {
    if (req.session.loggedin != true) {
        res.render("login", { error: null });
    } else {
        res.redirect("/");
    }
}

function auth(req, res) {
    const data = req.body;
    const connection = req.db;

    connection.query("SELECT * FROM user WHERE email = ?", [data.email], (err, userData) => {
        if (err) {
            console.error("Error al buscar usuario en la base de datos:", err);
            res.status(500).send("Error interno del servidor");
            return;
        }

        if (userData.length > 0) {
            const user = userData[0];
            bcrypt.compare(data.password, user.password, (err, isMatch) => {
                if (err) {
                    console.error("Error al comparar contraseñas:", err);
                    res.status(500).send("Error interno del servidor");
                    return;
                }
                if (!isMatch) {
                    res.render("login/index", { error: "Clave incorrecta" });
                } else {
                    req.session.loggedin = true;
                    req.session.name = user.name;
                    req.session.roles = typeof user.roles === 'string' ? user.roles.split(',') : [];

                    res.redirect("/");
                }
            });
        } else {
            res.render("login/index", { error: "El usuario no existe" });
        }
    });
}

function register(req, res) {
    if (req.session.loggedin != true) {
        res.render("login/register", { error: null });
    } else {
        res.redirect("/");
    }
}

function storeUser(req, res) {
    const data = req.body;
    const connection = req.db;

    connection.query("SELECT * FROM user WHERE email = ?", [data.email], (err, userData) => {
        if (err) {
            console.error("Error al buscar usuario en la base de datos:", err);
            res.status(500).send("Error interno del servidor");
            return;
        }

        if (userData.length > 0) {
            res.render("login/register", { error: "Ya existe un usuario con ese correo electrónico" });
            return;
        }

        bcrypt.hash(data.password, 12)
            .then(hash => {
                data.password = hash;
                connection.query("INSERT INTO user SET ?", data, (err, rows) => {
                    if (err) {
                        console.error("Error al insertar usuario en la base de datos:", err);
                        res.status(500).send("Error interno del servidor");
                    } else {
                        console.log("Usuario registrado correctamente");
                        res.redirect("/");
                    }
                });
            })
            .catch(err => {
                console.error("Error al cifrar la contraseña:", err);
                res.status(500).send("Error interno del servidor");
            });
    });
}

function logout(req, res) {
    if (req.session.loggedin == true) {
        req.session.destroy();
        res.redirect("/login");
    } else {
        res.redirect("/login");
    }
}

module.exports = {
    login,
    register,
    storeUser,
    auth,
    logout,
};
