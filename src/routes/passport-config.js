import passport from 'passport';
import local from 'passport-local';
import crypto from 'crypto';
import GitHubStrategy from 'passport-github2';
import managermd from '../dao/managermd.js'
import { userModel } from '../dao/models/user.model.js';
import {isValidPassword} from '../util.js';

const inicializaPassport = () => {

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

passport.use('loginGitHub', new GitHubStrategy.Strategy({

  clientID:'Iv1.70ce45700889066b',
  clientSecret: 'd16c7f73c24156ac574b5954679c2c3b817e4e3b',
  callbackURL: 'http://localhost8080/api/sessions/callbackGithub'

  }, async(token,tokenfresh, profile, done)=> {
    try {
      let usuario= await managermd.obtenerUsuarioPorEmail(profile._json.email)
      if(!usuario) {
        let typeofuser='user'
        await managermd.crearUsuario (profile._json.name,profile._json.email,'',typeofuser)
        return done (null,user)
      } else {
        return done (nul,usuario)
      }
  
    } catch (error){
      return done (error)
    }
  
  }) )

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

/*

passport.use(
  new GitHubStrategy(
    {
      clientID: 'YOUR_GITHUB_CLIENT_ID',
      clientSecret: 'YOUR_GITHUB_CLIENT_SECRET',
      callbackURL: 'http://localhost:3000/auth/github/callback', // Change to your callback URL
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        // Check if the user already exists in your database
        let user = await userModel.findOne({ githubId: profile.id });

        if (!user) {
          // If not, create a new user
          user = new userModel({
            githubId: profile.id,
            name: profile.displayName,
            email: profile.emails[0].value,
            // Other user properties here
          });

          await user.save();
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
)*/
  

function validarCorreoElectronico(correo) {
  const expresionRegular = /^[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}$/;
  return expresionRegular.test(correo);
}
}
export default inicializaPassport