import mongoose from 'mongoose';
import {productModel} from '../dao/models/user.model.js';
import {Router} from 'express';
import { body, validationResult } from 'express-validator';
import { ObjectId } from 'mongodb';
import  {managermd} from '../dao/managermd.js'

const router = Router ()

// Conectar a la base de datos MongoDB Atlas
mongoose.connect('mongodb+srv://omardagostino:laly9853@cluster0.x1lr5sc.mongodb.net/ecommerce1');


// Rutas para productos

// validaciones de los datos de los productos nuevos

  const validateAddProduct = [
      body('title').notEmpty().isString(),
      body('description').notEmpty().isString(),
      body('code').notEmpty().isString(),
      body('price').notEmpty().isNumeric(),
      body('stock').notEmpty().isNumeric(),
      body('category').notEmpty().isString(),
      body('status').optional().isBoolean(),
      (req, res, next) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
          res.setHeader('Content-Type','application/json');
          return res.status(400).json({ errors: errors.array() });
        }
        next();
      }
    ];

// Validaciones de las datos de los productos a actualizar
  
  const validateUpdateProduct = [
    body('title').optional().isString(),
    body('description').optional().isString(),
    body('code').optional().isString(),
    body('price').optional().isNumeric(),
    body('stock').optional().isNumeric(),
    body('category').optional().isString(),
    body('status').optional().isBoolean(),
     (req, res, next) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        res.setHeader('Content-Type','application/json');
        return res.status(400).json({ errors: errors.array() });
      }
      next();
    }
  ];


// GET para retornar varios productos o todos
router.get('/products', async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 10;
    const page = parseInt(req.query.page) || 1;
    const sortOrder = req.query.sort; 
    const query = req.query.query || ''; 
    const filter = {}; 
    if (req.query.category) {
      filter.category = req.query.category; 
    }
    if (req.query.stock) {
      filter.stock = req.query.stock; 
    }
     
    const options = {
      page,
      limit,
      sort: sortOrder ? { price: sortOrder === 'desc' ? -1 : 1 } : null,
    };
    const combinedFilter = {
      ...filter
    };

    const products = await managermd.obtenerProductos(combinedFilter, options);

    const prevPage = page > 1 ? page - 1 : null;
    const nextPage = page < products.totalPages ? page + 1 : null;

    const response = {
      status: 'success',
      payload: products.docs,
      totalPages: products.totalPages,
      prevPage,
      nextPage,
      page,
      hasPrevPage: products.hasPrevPage,
      hasNextPage: products.hasNextPage,
      prevLink: prevPage ? `/products?page=${prevPage}&limit=${limit}&sort=${sortOrder}&query=${query}` : null,
      nextLink: nextPage ? `/products?page=${nextPage}&limit=${limit}&sort=${sortOrder}&query=${query}` : null,
    };

    res.json(response);
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'Error en el servidor',error });
    console.error(error)
  }
});

// GET para retornar un producto por su ID
router.get('/products/:pid', async (req, res) => {
  try {
    const productId = req.params.pid;
    const validObjectId = ObjectId.isValid(productId) ? new ObjectId(productId) : null;
    if (!validObjectId) { 
      res.status(404).send("Identificador de Producto invalido");
      } else {
        const product = await managermd.obtenerProducto(productId);
        if (product) {
          res.json(product);
        } else {
          res.status(404).send('Producto no encontrado');
        }
      }
  } catch (error) {
    res.status(500).send(`Error en el servidor ${error}`);
  }
});

// POST para crear un nuevo producto
router.post('/products', validateAddProduct, async (req, res) => {
    try {
      const newProduct = req.body;
  
      // Verificar si el producto ya existe por su código
      const existingProduct = await managermd.obtenerProductoPorCodigo();
      if (existingProduct) {
        res.status(400).send('El producto con este código ya existe');
        return;
      }
  
      const product = new productModel({ ...newProduct});
      await managermd.crearProducto(product);
  
      res.status(201).json(product);
    } catch (error) {
      res.status(500).send('Error en el servidor');
    }
  });
  

// PUT para actualizar un producto por su ID
router.put('/products/:pid', validateUpdateProduct, async (req, res) => {
  try {
    const productId = req.params.pid;
    const updatedProduct = req.body;
    const validObjectId = ObjectId.isValid(productId) ? new ObjectId(productId) : null;
    if (!validObjectId) { 
      res.status(404).send("Identificador de Producto invalido");
      } else {


    const product = await managermd.obtenerProducto(productId);

    if (!product) {
      res.status(404).send('Producto no encontrado');
      return;
    }

    // Actualizar el producto
    for (const key in updatedProduct) {
      if (updatedProduct.hasOwnProperty(key)) {
        product[key] = updatedProduct[key];
      }
    }

    await managermd.actualizarProducto(product,productId);

    res.status(200).json(product);
  }
  } catch (error) {
    res.status(500).send('Error en el servidor');
  }
});

// DELETE para eliminar un producto por su ID
router.delete('/products/:pid', async (req, res) => {
  try {
    const productId = req.params.pid;
    const validObjectId = ObjectId.isValid(productId) ? new ObjectId(productId) : null;
    if (!validObjectId) { 
      res.status(404).send("Identificador de Producto invalido");
      } else {

    const product = await managermd.obtenerProducto(productId);

    if (!product) {
      res.status(404).send('Producto no encontrado');
      return;
    }

    await managermd.eliminarProducto(productId)
    res.status(200).send(`Producto con ID ${productId} eliminado`)
  }
  } catch (error) {
    console.error(error)
    res.status(500).send('Error en el servidor')
  }
});

export default router;
