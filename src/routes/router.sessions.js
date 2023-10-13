import {Router} from 'express'
import bodyParser from 'body-parser'
import {managermd} from '../dao/managermd.js'
import crypto from 'crypto'
export const router = Router ()
router.use(bodyParser.urlencoded({ extended: true }));
import passport from 'passport'; 
import  inicializaPassport from './passport-config.js';
import { userModel } from '../dao/models/user.model.js';

// Ruta para autenticación de GitHub
// router.get('/auth/github', passport.authenticate('github'));

// Callback de autenticación de GitHub
// router.get(
//  '/auth/github/callback',
// passport.authenticate('github', {
//   successRedirect: '/products', // Ruta de éxito después de autenticar
//  failureRedirect: '/login?error=Falló la autenticación de GitHub', // Ruta en caso de error
//  })
// );


// Registro de un nuevo usuario con GitHub
// router.get('/auth/github', passport.authenticate('github'));

// Callback de autenticación de GitHub
// router.get(
// '/auth/github/callback',
//  passport.authenticate('github', {
//   successRedirect: '/products', 
//   failureRedirect: '/login?error=Falló la autenticación de GitHub',
//  })
// );

// Login con error

router.get ('/errorLogin', (req,res) => {
    res.redirect('/login?error=Login con error')    
    });

// Login de Git Hub con error

router.get ('/errorLoginGitHub', (req,res) => {
    res.redirect('/loginGitHub?error=**Login con error**')    
    });

// registro con error

router.get ('/errorRegistro', (req,res) => {
    res.redirect('/registro?error=Error de registro')    
    });

// Registro de un nuevo usuario 

router.post('/registro', passport.authenticate('registro', {
    failureRedirect: '/api/sesions/errorRegistro',
    successRedirect: '/login', // Redirección exitosa
    session: false, // Desactiva la creación de sesiones
}))

// Login de un usuario o del administrador
router.post('/login', passport.authenticate('login', { failureRedirect: '/api/sesions/errorLogin' }), (req, res, next) => {
    
   
    req.session.usuario = req.user;
    
  
    if (req.user && req.user.email === 'adminCoder@coder.com') {
      // Establece una propiedad 'admin' en la sesión para identificar al administrador
      req.session.admin = true;
    }
  
    if (req.session.admin) {
      return res.redirect('/admin'); // Redirige al administrador
    } else {
      return res.redirect('/products'); // Redirige al usuario
    }
  })
  
// Login con GitHub
router.get('/loginGitHub', passport.authenticate('loginGitHub', {}), (req, res, next) => { });  

router.get('/callbackGithub',  passport.authenticate('loginGitHub', 
        { 
            failureRedirect: '/api/sesions/errorLoginGitHub'
            
        } 
    ),(req, res, next) => { 
   
    req.session.usuario = req.user;
    return res.redirect ('/products')
    });  


// logOut

router.get('/logout', async (req,res) => {

    req.session.destroy(e=> console.error(e)),
    res.redirect('/login?mensaje=logout correcto... !')

})

function validarCorreoElectronico(correo) {
    const expresionRegular = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
    return expresionRegular.test(correo);
  }
  
  