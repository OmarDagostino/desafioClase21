# Desafío de la clase 19
# Comisión 55565  de CoderHouse

## Autor : Omar D'Agostino

## Tecnologías utilizadas : 
- Node JS : v18.16.1
- Motor de plantillas : Handlebars
- Websocket : socket.io
- Mongo DB Atlas usado con Mongoose
    -base de datos : ecommerce1
    -colecciones : products1 / carts1 / messages1 /sessions / users1
- Dependencias 
    - "connect-mongo": "^5.0.0",
    - "crypto": "^1.0.1",
    - "express": "^4.18.2",
    - "express-handlebars": "^7.1.2",
    - "express-session": "^1.17.3",
    - "express-validator": "^7.0.1",
    - "mongoose": "^7.5.1",
    - "mongoose-paginate-v2": "^1.7.4",
    - "nodemon": "^3.0.1",
    - "socket.io": "^4.7.2",
    - "socket.io-client": "^4.7.2"

## Funcionalidades agregadas 

    * se agrego el registro de usuarios con nombre, email y  password, con sus respectiva validaciones.

    * se creo un login que debe informar email y password y deben coincidir con las registradas

    * todos los errores se renderizan en la misma pagina 

    * se creo un perfil de administrador hardcodeado y no se graba en la coleccion de users1

   
   

   

   Nota : Se desconecto el manejador de rutas de File System , pero no se eliminó (quedo en un manager separado y se comento en el código de app.js)
