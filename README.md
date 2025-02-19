# Advanced Products Dashboard

A modern web application for managing and showcasing advanced products with user authentication and dashboard functionality.

## Features

- User Authentication (Login/Signup)
- Secure Dashboard
- Product Management
- Responsive Design
- Modern UI with FontAwesome Icons

## Tech Stack

- Frontend: HTML, CSS, JavaScript
- Backend: Node.js, Express
- Database: MongoDB
- Authentication: JWT

## Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/mayankverma74/advanced-products.git
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Create a .env file in the root directory with the following variables:
   ```
   MONGODB_URI=your_mongodb_uri
   JWT_SECRET=your_jwt_secret
   ```

4. Start the server:
   ```bash
   npm start
   ```

5. Open http://localhost:3000 in your browser

## Project Structure

```
advanced-products/
├── public/          # Static files
├── models/          # Database models
├── server.js        # Express server
├── package.json     # Dependencies
└── README.md        # Documentation
```

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## License

[MIT](https://choosealicense.com/licenses/mit/)
