const express = require('express');
const cors = require('cors');
const admin = require("firebase-admin");
require('dotenv').config();
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const superAdminEmail = process.env.SUPER_ADMIN_EMAIL;

const app = express();
const port = process.env.PORT || 5000;

// Middleware
const corsOptions = {
    origin: ['http://localhost:5173'],
    credentials: true, // allow cookies and headers
};

app.use(cors(corsOptions));
app.use(express.json());

// Logging Middleware
const logger = (req, res, next) => {
    const log = `[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`;
    if (process.env.NODE_ENV !== 'production') {
        console.log(log);
    }
    next();
};

app.use(logger); // Use it directly



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

        const upcomingMealsCollection = db.collection('upcoming_meals')

        const mealRequestsCollection = db.collection('meal_requests');


        // Custom Middleware for FirebaseAccessToken
        const verifyFBToken = async (req, res, next) => {
            const authHeader = req.headers.authorization;
            console.log("🔐 Incoming Authorization Header:", req.headers.authorization);
            if (!authHeader) {
                return res.status(401).send({ message: 'unauthorized access' })
            }
            const token = authHeader.split(' ')[1];
            if (!token) {
                return res.status(401).send({ message: 'unauthorized access' })
            }
            // verify the token

            try {
                const decoded = await admin.auth().verifyIdToken(token)
                req.decoded = decoded

                next();
            }
            catch (err) {
                console.error("❌ Token verification failed:", err.message);
                return res.status(401).send({ message: 'Unauthorized: Invalid token' });
            }

        }


        const verifyAdmin = async (req, res, next) => {
            const decodedEmail = req.decoded?.email;

            if (!decodedEmail) {
                return res.status(401).send({ message: "Unauthorized" });
            }

            const user = await usersCollection.findOne({ email: decodedEmail });

            if (user?.role !== 'admin') {
                return res.status(403).send({ message: "Forbidden: Admins only" });
            }

            next();
        };


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
        app.patch('/users/role/:id', verifyFBToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;
            const { makeAdmin, requesterEmail } = req.body;

            try {
                // Step 1: Check if the requester is the super admin
                if (requesterEmail !== superAdminEmail) {
                    return res.status(403).send({ message: "Only the System admin can update roles." });
                }

                // Step 2: Prevent removing super admin itself
                const targetUser = await usersCollection.findOne({ _id: new ObjectId(id) });
                if (targetUser?.email === superAdminEmail && !makeAdmin) {
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



        // Get current logged-in user from token
        app.get('/current/user', verifyFBToken, async (req, res) => {
            const email = req.decoded.email;
            try {
                const user = await usersCollection.findOne({ email });
                if (!user) return res.status(404).send({ message: 'User not found' });
                res.send(user);
            } catch (err) {
                res.status(500).send({ message: 'Failed to fetch user data', err });
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





        // get meals 
        app.get('/meals', verifyFBToken, verifyAdmin, async (req, res) => {
            const sortField = req.query.sort || 'likes';
            const sortOrder = req.query.order === 'asc' ? 1 : -1;
            const search = req.query.search || '';

            const query = search ? { title: { $regex: search, $options: 'i' } } : {};

            try {
                let sortStage = {};

                if (sortField === 'category') {
                    // custom order mapping
                    const categoryOrder = {
                        'Breakfast': 1,
                        'Lunch': 2,
                        'Dinner': 3,
                        'Special Breakfast': 4,
                        'Special Lunch': 5,
                        'Special Dinner': 6
                    };

                    const pipeline = [
                        { $match: query },
                        {
                            $addFields: {
                                categoryOrder: {
                                    $switch: {
                                        branches: Object.entries(categoryOrder).map(([category, order]) => ({
                                            case: { $eq: ["$category", category] },
                                            then: order
                                        })),
                                        default: 999
                                    }
                                }
                            }
                        },
                        { $sort: { categoryOrder: sortOrder } }
                    ];

                    const meals = await mealsCollection.aggregate(pipeline).toArray();
                    return res.send(meals);
                }

                // other sorting (likes, reviews_count, postTime)
                sortStage[sortField] = sortOrder;

                const meals = await mealsCollection
                    .find(query)
                    .sort(sortStage)
                    .toArray();

                res.send(meals);
            } catch (error) {
                res.status(500).send({ message: 'Error fetching meals', error });
            }
        });



        // Assuming your existing setup & client/db initialization above

        app.get('/meals-filter-info', async (req, res) => {
            try {
                const categoryResult = await mealsCollection.aggregate([
                    {
                        $group: {
                            _id: '$category'
                        }
                    },
                    {
                        $project: {
                            _id: 0,
                            category: '$_id'
                        }
                    }
                ]).toArray();
                const categories = categoryResult.map(c => c.category);

                const priceStats = await mealsCollection.aggregate([
                    {
                        $group: {
                            _id: null,
                            minPrice: { $min: '$price' },
                            maxPrice: { $max: '$price' },
                        },
                    },
                ]).toArray();

                const minPrice = priceStats.length > 0 ? priceStats[0].minPrice : 0;
                const maxPrice = priceStats.length > 0 ? priceStats[0].maxPrice : 1000;

                res.send({ categories, minPrice, maxPrice });
            } catch (error) {
                console.error('Failed to fetch filter info:', error);
                res.status(500).send({ message: 'Failed to fetch filter info', error });
            }
        });



        // GET Meals for user and admin both
        app.get('/meals-public', verifyFBToken, async (req, res) => {
            const {
                search = '',
                category,
                minPrice,
                maxPrice,
                page = 1,
                limit = 10,
            } = req.query;

            const filter = {};

            if (search) {
                filter.title = { $regex: search, $options: 'i' };
            }

            if (category && category !== 'All') {
                filter.category = category;
            }

            if (minPrice || maxPrice) {
                filter.price = {};
                if (minPrice) filter.price.$gte = Number(minPrice);
                if (maxPrice) filter.price.$lte = Number(maxPrice);
            }

            const skip = (parseInt(page) - 1) * parseInt(limit);

            try {
                const meals = await mealsCollection
                    .find(filter)
                    .skip(skip)
                    .limit(parseInt(limit))
                    .toArray();

                res.send({ meals });
            } catch (err) {
                res.status(500).send({ message: 'Public meal fetch failed', err });
            }
        });




        // GET Single meal by ID
        app.get('/meals/:id', verifyFBToken, async (req, res) => {
            const id = req.params.id;

            try {
                const meal = await mealsCollection.findOne({ _id: new ObjectId(id) });
                if (!meal) return res.status(404).send({ message: 'Meal not found' });
                res.send(meal);
            } catch (error) {
                res.status(500).send({ message: 'Failed to fetch meal', error });
            }
        });



        // PATCH /meals/like/:id
        app.patch('/meals/like/:id', verifyFBToken, async (req, res) => {
            const mealId = req.params.id;
            const userEmail = req.decoded.email;

            try {
                const meal = await mealsCollection.findOne({ _id: new ObjectId(mealId) });

                if (!meal) {
                    return res.status(404).send({ message: 'Meal not found' });
                }

                const alreadyLiked = meal.likedBy?.includes(userEmail);

                const update = alreadyLiked
                    ? {
                        $inc: { likes: -1 },
                        $pull: { likedBy: userEmail }
                    }
                    : {
                        $inc: { likes: 1 },
                        $addToSet: { likedBy: userEmail }
                    };

                const result = await mealsCollection.updateOne(
                    { _id: new ObjectId(mealId) },
                    update
                );

                res.send({ success: result.modifiedCount > 0, liked: !alreadyLiked });
            } catch (err) {
                res.status(500).send({ message: 'Failed to toggle like', error: err });
            }
        });









        app.post('/meal-requests', verifyFBToken, async (req, res) => {
            const { mealId, userEmail, status } = req.body;

            if (!mealId || !userEmail) {
                return res.status(400).send({ message: 'Missing required fields' });
            }

            const exists = await mealRequestsCollection.findOne({ mealId, userEmail });
            if (exists) {
                return res.status(400).send({ message: 'Already requested' });
            }

            const result = await mealRequestsCollection.insertOne({
                mealId,
                userEmail,
                status: status || 'pending',
                requestedAt: new Date().toISOString()
            });

            res.status(201).send({ message: 'Meal requested', insertedId: result.insertedId });
        });






        app.post('/meal-reviews', verifyFBToken, async (req, res) => {
            const { mealId, email, name, image, review } = req.body;

            if (!mealId || !review || !email || !name) {
                return res.status(400).send({ message: 'Missing review info' });
            }

            const reviewDoc = {
                mealId,
                email,
                name,
                image,
                review,
                createdAt: new Date().toISOString()
            };

            try {
                const result = await mealsCollection.updateOne(
                    { _id: new ObjectId(mealId) },
                    {
                        $push: { reviews: reviewDoc },
                        $inc: { reviews_count: 1 }
                    }
                );

                if (result.modifiedCount > 0) {
                    res.send({ message: 'Review added', success: true });
                } else {
                    res.status(404).send({ message: 'Meal not found' });
                }
            } catch (error) {
                res.status(500).send({ message: 'Failed to add review', error });
            }
        });




        // delete Meal
        app.delete('/meals/:id', verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const id = req.params.id;
                const result = await mealsCollection.deleteOne({ _id: new ObjectId(id) });
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: 'Failed to delete meal' });
            }
        });



        // GET all upcoming meals, sorted by likes
        app.get('/upcoming-meals', verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const upcoming = await upcomingMealsCollection
                    .find()
                    .sort({ likes: -1 })
                    .toArray();

                res.send(upcoming);
            } catch (err) {
                res.status(500).send({ message: 'Failed to fetch upcoming meals', err });
            }
        });



        // ১. ক্যাটাগরি, minPrice, maxPrice ফেরত দিবে (filter info)
        app.get('/upcoming-meals-filter', async (req, res) => {
            try {
                const categoryResult = await upcomingMealsCollection.aggregate([
                    { $group: { _id: '$category' } },
                    { $project: { _id: 0, category: '$_id' } }
                ]).toArray();

                const categories = categoryResult.map(c => c.category);

                const priceStats = await upcomingMealsCollection.aggregate([
                    {
                        $group: {
                            _id: null,
                            minPrice: { $min: '$price' },
                            maxPrice: { $max: '$price' }
                        }
                    }
                ]).toArray();

                const minPrice = priceStats.length > 0 ? priceStats[0].minPrice : 0;
                const maxPrice = priceStats.length > 0 ? priceStats[0].maxPrice : 1000;

                res.send({ categories, minPrice, maxPrice });
            } catch (error) {
                console.error('Failed to fetch upcoming meals filter info:', error);
                res.status(500).send({ message: 'Failed to fetch filter info', error });
            }
        });



        // ২. সার্চ, ক্যাটাগরি, প্রাইস রেঞ্জ, পেজিনেশনসহ মিলস রিটার্ন করবে + likes দিয়ে sort করবে
        app.get('/upcoming-meals-public', verifyFBToken, async (req, res) => {
            const {
                search = '',
                category,
                minPrice,
                maxPrice,
                page = 1,
                limit = 10,
            } = req.query;

            const filter = {};

            if (search) {
                filter.title = { $regex: search, $options: 'i' };
            }

            if (category && category !== 'All') {
                filter.category = category;
            }

            if (minPrice || maxPrice) {
                filter.price = {};
                if (minPrice) filter.price.$gte = Number(minPrice);
                if (maxPrice) filter.price.$lte = Number(maxPrice);
            }

            const skip = (parseInt(page) - 1) * parseInt(limit);

            try {
                const totalCount = await upcomingMealsCollection.countDocuments(filter);

                const meals = await upcomingMealsCollection
                    .find(filter)
                    .sort({ likes: -1 })
                    .skip(skip)
                    .limit(parseInt(limit))
                    .toArray();

                res.send({ meals, totalCount });
            } catch (err) {
                res.status(500).send({ message: 'Public upcoming meals fetch failed', err });
            }
        });



        // ৩. Like/Unlike টগল (upcoming meals এর জন্য)
        app.patch('/upcoming-meals/like/:id', verifyFBToken, async (req, res) => {
            const mealId = req.params.id;
            const userEmail = req.decoded.email;

            try {
                const meal = await upcomingMealsCollection.findOne({ _id: new ObjectId(mealId) });

                if (!meal) {
                    return res.status(404).send({ message: 'Meal not found' });
                }

                const alreadyLiked = meal.likedBy?.includes(userEmail);

                const update = alreadyLiked
                    ? {
                        $inc: { likes: -1 },
                        $pull: { likedBy: userEmail }
                    }
                    : {
                        $inc: { likes: 1 },
                        $addToSet: { likedBy: userEmail }
                    };

                const result = await upcomingMealsCollection.updateOne(
                    { _id: new ObjectId(mealId) },
                    update
                );

                res.send({ success: result.modifiedCount > 0, liked: !alreadyLiked });
            } catch (err) {
                res.status(500).send({ message: 'Failed to toggle like', error: err });
            }
        });





        // Post Up-coming Meals
        app.post('/upcoming-meals', verifyFBToken, verifyAdmin, async (req, res) => {
            const meal = req.body;
            meal.likes = 0;
            meal.reviews_count = 0;
            meal.rating = 0;
            meal.createdAt = new Date().toISOString();

            try {
                const result = await upcomingMealsCollection.insertOne(meal);
                res.send({ insertedId: result.insertedId });
            } catch (err) {
                res.status(500).send({ message: 'Failed to add upcoming meal', err });
            }
        });




        // puslish upcoming meals to main meals collection
        app.post('/publish-meal/:id', verifyFBToken, verifyAdmin, async (req, res) => {
            const id = req.params.id;

            try {
                const meal = await upcomingMealsCollection.findOne({ _id: new ObjectId(id) });

                if (!meal) return res.status(404).send({ message: 'Meal not found' });

                meal.postTime = new Date().toISOString();
                // Insert to meals collection
                await mealsCollection.insertOne(meal);

                // Delete from upcoming
                await upcomingMealsCollection.deleteOne({ _id: new ObjectId(id) });

                res.send({ message: 'Meal published successfully' });
            } catch (err) {
                res.status(500).send({ message: 'Publish failed', err });
            }
        });



        // Count meals & upcoming meals added by current admin
        app.get('/total-meals', verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const email = req.decoded.email;

                const mealsCount = await mealsCollection.countDocuments({
                    $or: [
                        { distributorEmail: email },
                        { distributor_email: email }
                    ]
                });

                const upcomingCount = await upcomingMealsCollection.countDocuments({
                    $or: [
                        { distributorEmail: email },
                        { distributor_email: email }
                    ]
                });

                res.send({ mealsCount, upcomingCount });

            } catch (err) {
                console.error('Failed to count meals by admin:', err);
                res.status(500).send({ message: 'Failed to count meals', error: err });
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