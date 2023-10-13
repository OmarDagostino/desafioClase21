import passport from 'passport';
import local from 'passport-local';
import crypto from 'crypto';
import GitHubStrategy from 'passport-github2';
import managermd from '../dao/managermd.js'
import { userModel } from '../dao/models/user.model.js';
import {isValidPassword} from '../util.js';

const inicializaPassport = () => {

// Registrar un usuario nuevo con email y password

passport.use ('registro', new local.Strategy(
    {
      usernameField : 'email', passReqToCallback : true
    },
    async (req,username,password, done) => { 
       
      const {name, email} = req.body;
        
      try {
        
        if (!name || !username || !password) {
        done (null,false)
      }
      
      if (!validarCorreoElectronico(username)) {
          done (null, false)
      }
      
      const existeUsuario = await managermd.obtenerUsuarioPorEmail(username)
      if (existeUsuario) {
         done (null, false)
      }
      
      password=crypto.createHmac('sha256','palabraSecreta').update(password).digest('base64')
      let typeofuser='user'
      const usuario = managermd.crearUsuario(name,email,password,typeofuser)
        
      done (null,usuario)
      
      }
    catch (error){
      done(error)
    }
  }
  )),
// fin de Registrar un usuario nuevo con Email y password

// Hacer Login de un usuario o del administrador con Email y Password

passport.use('login', new local.Strategy({
usernameField:'email', passReqToCallback : true
}, async(req,username, password, done)=> {
  try {
   
    const emailAdministrador = 'adminCoder@coder.com'
    const passwordAdministrador = 'adminCod3r123'

    if (username === emailAdministrador && password === passwordAdministrador) {
      // Si las credenciales coinciden con el administrador
      const adminUsuario = {
        nombre: 'Administrador',
        carrito: null,
        email: username,
        typeofuser: 'admin',
        id: '1',
      };
      return done(null, adminUsuario);
    }

    if (!username || !password) {
       return done (null,false)
    }
    password=crypto.createHmac('sha256','palabraSecreta').update(password).digest('base64')
  
    req.usuario = await managermd.obtenerUsuarioPorEmail({username })
  
    if(!req.usuario) {
      return done (null,false)
    } else {
      
    if (!isValidPassword(password,req.usuario.password)) {
      return done (null,false)
    } 
    
    return done (null,req.usuario)}

  } catch (error){
    return done (error)
  }

}) )

// fin de hacer login de un usuario o administrador con email y password

// hacer Login con Git Hub

passport.use('loginGitHub', new GitHubStrategy.Strategy({

  clientID:'Iv1.70ce45700889066b',
  
  // aqui se deben colocar los datos del cliente id y client secret 
  

  }, async(token,tokenfresh, profile, done)=> {
    try {
      let username = profile._json.email
      let usuario= await managermd.obtenerUsuarioPorEmail({username})
         
      if(!usuario) {
        let typeofuser='user'
        usuario = await managermd.crearUsuario (profile._json.name,profile._json.email,'github',typeofuser)
        
        return done (null,usuario)
      } else {
        return done (null,usuario)
      }
  
    } catch (error){
      return done (error)
    }
  
  }) )

// fin de hacer Login con Git Hub

// manejo de sesiones con passport

passport.serializeUser((usuario, done) => {
  done(null, usuario.id);
});

passport.deserializeUser(async (id, done) => {
    if (id!=='1') {let usuario = await managermd.obtenerUsuarioPorId (id);
    done(null,usuario)
  } else {
    let usuario = {
      nombre : 'Administrador',
      carrito : null,
      email : 'adminCoder@coder.com',
      typeofuser : 'admin',
      id:'1'
    };
    done(null, usuario)
  }
  }
);

// fin del manejo de sesiones con passport

// funcion para validar el formato del correo electronico

function validarCorreoElectronico(correo) {
  const expresionRegular = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
  return expresionRegular.test(correo);
}

// fin de la funcion para validar el formato del correo electronico

}

export default inicializaPassport