# Desafío de la clase 21
# Comisión 55565  de CoderHouse

## Autor : Omar D'Agostino

## Tecnologías utilizadas : 
- Node JS : v18.16.1
- Motor de plantillas : Handlebars
- Estrategias de autenticación : Passport local y Passport con Git Hub
- Hasheo de password : Bcrypt
- Websocket : socket.io
- Mongo DB Atlas usado con Mongoose
    -base de datos : ecommerce1
    -colecciones : products1 / carts1 / messages1 /sessions / users1
- Dependencias 
    "bcrypt": "^5.1.1",
    "connect-mongo": "^5.0.0",
    "crypto": "^1.0.1",
    "express": "^4.18.2",
    "express-handlebars": "^7.1.2",
    "express-session": "^1.17.3",
    "express-validator": "^7.0.1",
    "mongoose": "^7.5.1",
    "mongoose-paginate-v2": "^1.7.4",
    "nodemon": "^3.0.1",
    "passport": "^0.6.0",
    "passport-github2": "^0.1.12",
    "passport-local": "^1.0.0",
    "socket.io": "^4.7.2",
    "socket.io-client": "^4.7.2"

## Funcionalidades agregadas 

    * se modificaron las autenticaciones para utilizar Passport en dos estrategias : local y a través de Git Hub, para ello se creo el archivo passport-config.js

    * Se hashean las password con Bcrypt

    * todos los errores se renderizan en la misma pagina 

   

   
   

   

   Nota : Se desconecto el manejador de rutas de File System , pero no se eliminó (quedo en un manager separado y se comento en el código de app.js)
