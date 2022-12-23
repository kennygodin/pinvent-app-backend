const dotenv = require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const userRoute = require('./routes/userRoutes');
const productRoute = require('./routes/productRoute');
const contactRoute = require('./routes/contactRoute');
const errorHandler = require('./middleware/errorMiddleware');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();

// middlewares
app.use(express.json());
app.use(cookieParser());
app.use(express.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(
  cors({
    origin: ['http://localhost:3000', 'https://pinvent-app-psi.vercel.app'],
    credentials: true,
  })
);

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// routes
app.get('/', (req, res) => {
  res.send('Homepage');
});

// routes middleware
app.use('/api/users', userRoute);
app.use('/api/products', productRoute);
app.use('/api/contactus', contactRoute);

// error middleware
app.use(errorHandler);

// connect to db and start server
const PORT = process.env.PORT || 5000;

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    app.listen(PORT, () =>
      console.log(`Connected to DB & Server Running on port ${PORT}`)
    );
  })
  .catch((err) => console.log(err));
