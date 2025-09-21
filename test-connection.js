const { MongoClient, ServerApiVersion } = require('mongodb');

// Your MongoDB connection string with the actual password
const uri = "mongodb+srv://ChatAppData:CHATAPPDATA@chatappdata.ua6pnti.mongodb.net/?retryWrites=true&w=majority&appName=ChatAppData";

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  }
});

async function testConnection() {
  try {
    console.log('🔄 Connecting to MongoDB Atlas...');
    
    // Connect the client to the server (optional starting in v4.7)
    await client.connect();
    
    // Send a ping to confirm a successful connection
    await client.db("admin").command({ ping: 1 });
    console.log("✅ Pinged your deployment. You successfully connected to MongoDB!");
    
    // Test creating a database and collection
    const database = client.db('ChatAppData');
    const collection = database.collection('users');
    
    // Insert a test document
    const testUser = {
      name: "Test User",
      username: "testuser",
      email: "test@example.com",
      createdAt: new Date()
    };
    
    const result = await collection.insertOne(testUser);
    console.log(`✅ Test document inserted with _id: ${result.insertedId}`);
    
    // Find the test document
    const foundUser = await collection.findOne({ username: "testuser" });
    console.log("✅ Found test document:", foundUser);
    
    // Delete the test document
    await collection.deleteOne({ _id: result.insertedId });
    console.log("✅ Test document deleted");
    
    // List all databases
    const databases = await client.db().admin().listDatabases();
    console.log("📋 Available databases:");
    databases.databases.forEach(db => console.log(`  - ${db.name}`));
    
  } catch (error) {
    console.error("❌ Connection failed:", error);
  } finally {
    // Ensures that the client will close when you finish/error
    await client.close();
    console.log("🔌 Connection closed");
  }
}

// Run the test
testConnection().catch(console.dir);
