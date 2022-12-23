const express = require('express');
const {
  createProduct,
  getProducts,
  getProduct,
  deleteProduct,
  updateProduct,
} = require('../controllers/productController');
const protect = require('../middleware/authMiddleware');
const { upload } = require('../utils/fileUpload');

const router = express.Router();
// Add or create a product
router.post('/', protect, upload.single('image'), createProduct);

// Get all products
router.get('/', protect, getProducts);

// Get a single product
router.get('/:id', protect, getProduct);

// Delete a single product
router.delete('/:id', protect, deleteProduct);

// Update a single product
router.patch('/:id', protect, upload.single('image'), updateProduct);
module.exports = router;
