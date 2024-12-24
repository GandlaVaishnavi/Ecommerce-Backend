// Project: Full Stack E-Commerce Application (Backend)
// Backend Implementation in Node.js with Express.js

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const app = express();
const PORT = 3000;

// Middleware
app.use(express.json());

// Database connection
mongoose.connect('mongodb://localhost:27017/ecommerce', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => console.log('Database connected')).catch(err => console.log(err));

// Models
const UserSchema = new mongoose.Schema({
  username: String,
  password: String,
  email: String,
  address: String,
  role: { type: String, default: 'user' },
});

const ProductSchema = new mongoose.Schema({
  name: String,
  description: String,
  price: Number,
  stock: Number,
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
});

const OrderSchema = new mongoose.Schema({
  user_id: mongoose.Schema.Types.ObjectId,
  total_amount: Number,
  status: { type: String, default: 'Pending' },
  created_at: { type: Date, default: Date.now },
  updated_at: { type: Date, default: Date.now },
});

const OrderItemSchema = new mongoose.Schema({
  order_id: mongoose.Schema.Types.ObjectId,
  product_id: mongoose.Schema.Types.ObjectId,
  quantity: Number,
  price: Number,
});

const User = mongoose.model('User', UserSchema);
const Product = mongoose.model('Product', ProductSchema);
const Order = mongoose.model('Order', OrderSchema);
const OrderItem = mongoose.model('OrderItem', OrderItemSchema);

// Utility functions
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ message: 'Access denied' });

  jwt.verify(token, 'secretkey', (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid token' });
    req.user = user;
    next();
  });
};

// Routes
// User Routes
app.post('/register', async (req, res) => {
  const { username, password, email, address } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  const user = new User({
    username,
    password: hashedPassword,
    email,
    address,
  });

  await user.save();
  res.status(201).json({ message: 'User registered successfully' });
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user) return res.status(404).json({ message: 'User not found' });

  const isPasswordValid = await bcrypt.compare(password, user.password);
  if (!isPasswordValid) return res.status(401).json({ message: 'Invalid credentials' });

  const token = jwt.sign({ id: user._id, role: user.role }, 'secretkey', { expiresIn: '1h' });
  res.json({ token });
});

app.get('/users/:id', authenticateToken, async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ message: 'User not found' });

  res.json(user);
});

app.put('/users/:id', authenticateToken, async (req, res) => {
  if (req.user.id !== req.params.id) return res.status(403).json({ message: 'Access denied' });

  const updatedUser = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(updatedUser);
});

// Product Routes
app.get('/products', async (req, res) => {
  const products = await Product.find();
  res.json(products);
});

app.get('/products/:id', async (req, res) => {
  const product = await Product.findById(req.params.id);
  if (!product) return res.status(404).json({ message: 'Product not found' });

  res.json(product);
});

app.post('/products', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });

  const product = new Product(req.body);
  await product.save();
  res.status(201).json(product);
});

app.put('/products/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });

  const updatedProduct = await Product.findByIdAndUpdate(req.params.id, req.body, { new: true });
  res.json(updatedProduct);
});

app.delete('/products/:id', authenticateToken, async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Access denied' });

  await Product.findByIdAndDelete(req.params.id);
  res.json({ message: 'Product deleted successfully' });
});

// Order Routes
app.post('/orders', authenticateToken, async (req, res) => {
  const { items, total_amount } = req.body;

  const order = new Order({
    user_id: req.user.id,
    total_amount,
  });

  await order.save();

  for (let item of items) {
    const orderItem = new OrderItem({
      order_id: order._id,
      ...item,
    });
    await orderItem.save();
  }

  res.status(201).json(order);
});

app.get('/orders', authenticateToken, async (req, res) => {
  const orders = await Order.find({ user_id: req.user.id });
  res.json(orders);
});

app.get('/orders/:id', authenticateToken, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order) return res.status(404).json({ message: 'Order not found' });

  res.json(order);
});

app.delete('/orders/:id', authenticateToken, async (req, res) => {
  const order = await Order.findById(req.params.id);
  if (!order || order.user_id.toString() !== req.user.id) {
    return res.status(403).json({ message: 'Access denied' });
  }

  await Order.findByIdAndDelete(req.params.id);
  res.json({ message: 'Order canceled successfully' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
