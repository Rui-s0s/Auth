import User from "./models/User.js";

async function addAdmin() {
  const admin = await User.createAdmin({
    username: "superadmin",
    email: "admin@example.com",
    password: "supersecurepassword"
  });
  
  console.log("Admin created:", admin.toSafeObject());
}

addAdmin();