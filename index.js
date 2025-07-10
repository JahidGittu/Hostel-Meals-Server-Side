const express = require('express');
const cors = require('cors');
const admin = require("firebase-admin");
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 5000;

// Middleware
const corsOptions = {
    origin: ['http://localhost:5173'],
    credentials: true, // allow cookies and headers
};

app.use(cors(corsOptions));

app.use(express.json());



// Firebase Admin sdk

const serviceAccount = require("./firebase-adminsdk-key.json");

admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});




// MongoDB client setup
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.tks1y5a.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;


// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();

        const db = client.db('Hostel_Management_System');
        const usersCollection = db.collection('users');

        const mealsCollection = db.collection('meals');



        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");



        // Check if user is admin
        app.get('/users/admin/:email', verifyFBToken, async (req, res) => {
            const email = req.params.email;

            if (req.decoded.email !== email) {
                return res.status(403).send({ isAdmin: false });
            }

            const user = await usersCollection.findOne({ email });

            res.send({ isAdmin: user?.role === 'admin' });
        });




        // users Search 
        app.get("/users/search", verifyFBToken, verifyAdmin, async (req, res) => {
            const query = req.query.query;
            if (!query) {
                return res.status(400).send({ message: "Missing search query" });
            }

            const regex = new RegExp(query, "i");

            try {
                const users = await usersCollection
                    .find({
                        $or: [
                            { name: { $regex: regex } },
                            { email: { $regex: new RegExp(`^${query}`, "i") } },
                            { email: { $regex: new RegExp(`^${query}@`, "i") } },
                            {
                                $expr: {
                                    $regexMatch: {
                                        input: { $arrayElemAt: [{ $split: ["$email", "@"] }, 0] },
                                        regex: regex
                                    }
                                }
                            }
                        ]
                    })
                    .project({ name: 1, email: 1, role: 1, created_At: 1, subscription: 1 })
                    .limit(10)
                    .toArray();

                res.send(users);
            } catch (error) {
                res.status(500).send({ message: "Search failed", error });
            }
        });





        // PATCH: Make Admin or Remove Admin
        app.patch('/users/role/:id', async (req, res) => {
            const id = req.params.id;
            const { makeAdmin, requesterEmail } = req.body;

            try {
                // Step 1: Check if the requester is the super admin
                if (requesterEmail !== 'code@gittu.com') {
                    return res.status(403).send({ message: "Only the System admin can update roles." });
                }

                // Step 2: Prevent removing super admin itself
                const targetUser = await usersCollection.findOne({ _id: new ObjectId(id) });
                if (targetUser?.email === 'code@gittu.com' && !makeAdmin) {
                    return res.status(403).send({ message: "You can't remove the System admin." });
                }

                // Step 3: Proceed with role update
                const result = await usersCollection.updateOne(
                    { _id: new ObjectId(id) },
                    { $set: { role: makeAdmin ? 'admin' : 'user' } }
                );

                res.send({ success: result.modifiedCount > 0 });
            } catch (error) {
                res.status(500).send({ message: 'Role update failed', error });
            }
        });





        // Example: POST /users to save user info
        app.post('/users', async (req, res) => {
            try {
                const user = req.body;
                const email = user.email;

                const userExists = await usersCollection.findOne({ email });

                if (userExists) {
                    // Update last login time
                    const updateResult = await usersCollection.updateOne(
                        { email },
                        { $set: { last_Log_In: new Date().toISOString() } }
                    );

                    return res.status(200).send({
                        message: 'User exists, last login time updated.',
                        updated: true,
                        inserted: false
                    });
                }

                const newUser = {
                    ...user,
                    created_At: new Date().toISOString(),
                    last_Log_In: new Date().toISOString(),
                };

                const result = await usersCollection.insertOne(newUser);

                res.status(201).send({
                    message: 'New user inserted successfully',
                    inserted: true,
                    data: result
                });
            } catch (error) {
                console.error('Error adding user:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });



        // POST: Add a Meal
        app.post('/meals', verifyFBToken, verifyAdmin, async (req, res) => {

            try {
                const meal = req.body;
                meal.rating = 0;
                meal.likes = 0;
                meal.reviews_count = 0;
                meal.postTime = new Date().toISOString();

                const result = await mealsCollection.insertOne(meal);

                res.status(201).send({ insertedId: result.insertedId });
            } catch (error) {
                console.error('Error adding meal:', error);
                res.status(500).send({ message: 'Failed to add meal', error });
            }
        });






    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);


app.get('/', (req, res) => {
    res.send("🍽️ “The Server Product for You — Now Cooked to Perfection… with Extra Spice!” 🌶️🔥")
})

app.listen(port, () => {
    console.log(`Server Running On Port ${port}`)
})