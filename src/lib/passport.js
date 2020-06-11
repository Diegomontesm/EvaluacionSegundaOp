const passport = require('passport');

const LocalStrategy = require('passport-local').Strategy;


const pool = require('../database')
const helpers = require('./helpers');

passport.use('local.signup', new LocalStrategy({
    NControlField: 'NControl',
    nombreField: 'Nombre',
    emailField: 'email',
    passwordField: 'password',
    semestreField: 'semestre',
    carreraField: 'carrera',
    passReqToCallback: true
},async (req, email, password, Nombre, semestre, carrera, done)=>{
    console.log(req.body);
    const {NControl} = req.body;
    const newUser={        
        email,
        password,
        NControl,
        Nombre,
        semestre,
        carrera
    };

    //INSERT A LA BD
    newUser.password = await helpers.encryptPassword(password);
    
    const result = pool.query('INSERT INTO alumno SET ? ', [newUser]);
    newUser.id = result.insertId;  
    console.log(result); 
    return done(null, newUser);
    
}));

//VALIDACION E INSERCION EN BASE DE DATOS DEL ALUMNO EN LA PANTALLA SIGNIN
 passport.use('local.signin', new LocalStrategy({
    emailField: 'email',
    passportField: 'password',
    passReqToCallback: true
}, async (req, email, password, done) => {
    const rows = await pool.query('SELECT * FROM alumno WHERE email = ?', [email]);
    if (rows.length > 0) {
        const user = rows[0];
        const validPassword = await helpers.matchPassword(password, user.password);
        if (validPassword) {
            done(null, user, req.flash('success', 'Bienvenido' + ' ' + user.email));

        } else {
            done(null, false, req.flash('message','Incorrect Password'));
        }
    } else {
        return done(null, false, req.flash('message','El correo electrónico no existe'));
    }
}
));



passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    const rows = await pool.query('SELECT * FROM alumno WHERE id = ?', [id]);
    done(null, rows[0]);
}); 