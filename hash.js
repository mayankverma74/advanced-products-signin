const bcrypt = require('bcrypt');

async function generateHash() {
    const password = "YASHWANT123"; // Change if needed
    const hash = await bcrypt.hash(password, 10);
    console.log("Hashed Password:", hash);
}

generateHash();
