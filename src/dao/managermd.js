import mongoose from 'mongoose';
import {cartModel} from './models/user.model.js';
import {productModel} from './models/user.model.js';
import {userModel} from './models/user.model.js';
import {Router} from 'express';
import { ObjectId } from 'mongodb';
import {createHash} from '../util.js';

const router = Router ()

// Conectar a la base de datos MongoDB Atlas
mongoose.connect('mongodb+srv://omardagostino:laly9853@cluster0.x1lr5sc.mongodb.net/ecommerce1');

export const managermd = { 
// Funciones para carritos

// Obtener un carrito por su ID
obtenerCarrito : async (cid)=>
{
  
  try {
    
    const cartId = cid;
    const validObjectId = ObjectId.isValid(cartId) ? new ObjectId(cartId) : null;
    if (!validObjectId) { 
      console.error("Identificador del carrito invalido");
      } else {
       
        const cart = await cartModel.findOne({ _id : cartId }).populate('products.productId');
       
        if (cart) {
          return(cart);
        } else {
          console.error('Carrito no encontrado');
        }
      }
  } catch (error) {
    console.error('Error en el servidor', error);
  }
},
obtenerCarritoSinPopulate : async (cid)=>
{
  
  try {
    
    const cartId = cid;
    const validObjectId = ObjectId.isValid(cartId) ? new ObjectId(cartId) : null;
    if (!validObjectId) { 
      console.error("Identificador del carrito invalido");
      } else {
       
        const cart = await cartModel.findOne({ _id : cartId });
       
        if (cart) {
          return(cart);
        } else {
          console.error('Carrito no encontrado');
        }
      }
  } catch (error) {
    console.error('Error en el servidor', error);
  }
},
// Actualizar un carrito
actualizarCarrito : async  (newcart,cid) =>
{
  try {
    const cartId = cid;
    const validObjectId = ObjectId.isValid(cartId) ? new ObjectId(cartId) : null;
    if (!validObjectId) { 
      console.error("Identificador del carrito invalido");
      } else {

        let cart = await cartModel.findOne({ _id : cartId }).exec();

        if (!cart) {
          console.error('Carrito no encontrado');
          return;
        }
            cart = newcart;
            await cart.save();
      
        }
      
  } catch (error) {
    console.error (`Error en el servidor ${error}`)
  }
},

// Crear un nuevo carrito
 crearCarrito: async (newcart) =>
{
    try {
     
      await newcart.save();
      
    }
     catch (error) {
      console.error(`Error en el servidor ${error}`);
    }
  },

 
 
// Funciones para productos

// obtener una lista de productos con filtros y paginaciones

obtenerProductos : async  (combinedFilter, options) =>
{
  try {
    const products = await productModel.paginate(combinedFilter, options);

    return (products);
  } catch (error) {
    console.error({ status: 'error', message: 'Error en el servidor',error });
    console.error(error)
  }
},

// obtener un producto por su ID
obtenerProducto : async (pid) =>
{
  try {
    const productId = pid ;
    const validObjectId = ObjectId.isValid(productId) ? new ObjectId(productId) : null;
    if (!validObjectId) { 
      console.error("Identificador de Producto invalido");
      } else {
        const product = await productModel.findOne({ _id: productId}).exec();
        if (product) {
          return (product);
        } else {
          console.error('Producto no encontrado');
        }
      }
  } catch (error) {
    console.error(`Error en el servidor ${error}`);
  }
},

// obtener un producto por su codigo

obtenerProductoPorCodigo : async (codigo) =>
{
  try {
  const existingProduct = await productModel.findOne({ code: codigo }).exec();
  return existingProduct
 }
 catch (error) {
  console.error(`Error en el servidor ${error}`);
  }
},

// Crear un nuevo producto
crearProducto : async (newProduct) =>
{
    try {
      
      const product = new productModel({ ...newProduct});
      await product.save();
  
      
    } catch (error) {
      console.error('Error en el servidor');
    }
  },
  

// actualizar un productos
actualizarProducto : async (producto,pid) =>
{
  try {
    const productId = pid;
    const updatedProduct = producto;
    const validObjectId = ObjectId.isValid(productId) ? new ObjectId(productId) : null;
    if (!validObjectId) { 
      console.error("Identificador de Producto invalido");
      } else {


    const product = await productModel.findOne({ _id : productId }).exec();

    if (!product) {
      console.error('Producto no encontrado');
      return;
    }

    await product.save();
    
  }
  } catch (error) {
    console.error('Error en el servidor');
  }
},

// Eliminar un producto por su ID
eliminarProducto : async (pid) => 
{
  try {
    const productId = pid;
    const validObjectId = ObjectId.isValid(productId) ? new ObjectId(productId) : null;
    if (!validObjectId) { 
      console.error("Identificador de Producto invalido");
      } else {

    const product = await productModel.findOne({ _id : productId }).exec();

    if (!product) {
      console.error('Producto no encontrado');
      return;
    }

    await product.deleteOne({ _id : productId })
    console.error(`Producto con ID ${productId} eliminado`)
  }
  } catch (error) {
    console.error(error)
    console.error('Error en el servidor')
  }
},

// Funciones para Manejo de usuarios

obtenerUsuarioPorEmail : async (direccionDeCorreo) =>
{
  try {
   
    const existingUser = await userModel.findOne({ email: direccionDeCorreo.username}).exec();
    return existingUser
   }
   catch (error) {
    console.error(`Error en el servidor ${error}`);
    }

},

obtenerUsuarioPorId : async (id) =>
{
  try {
   
    const existingUser = await userModel.findOne({ _id: id}).exec();
    return existingUser
   }
   catch (error) {
    console.error(`Error en el servidor ${error}`);
    }

},

crearUsuario : async (name,email,password,typeofuser) =>
{
  let cartId
  try {
    const newCart = new cartModel({
      products: []
    });
    await newCart.save();
    cartId = newCart._id
  }
   catch (error) {
    consosle.error(error)
  }

  try {
    password=createHash(password);
    const user = new userModel({name,email,password,cartId,typeofuser});
    await user.save();
    return user;

   }
   catch (error) {
    console.error(error);
    }
}

}

export default managermd
