const express = require('express');
const cors = require('cors');
const admin = require("firebase-admin");
require('dotenv').config();
const stripe = require('stripe')(process.env.STRIPE_PAYMENT_SECRET_KEY);
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const superAdminEmail = process.env.SUPER_ADMIN_EMAIL;

const app = express();
const port = process.env.PORT || 5000;

// Middleware
const corsOptions = {
    origin: ['http://localhost:5173','https://hostel-management-system-pro.web.app/'],
    credentials: true, // allow cookies and headers
};

app.use(cors(corsOptions));
app.use(express.json());


// Logging middleware
app.use((req, res, next) => {
    if (process.env.NODE_ENV !== 'production') {
        console.log(`[${new Date().toISOString()}] ${req.method} ${req.originalUrl}`);
    }
    next();
});

// ==================== HTTPS Redirect ====================
if (process.env.NODE_ENV === "production") {
    app.use((req, res, next) => {
        if (req.header("x-forwarded-proto") !== "https") {
            return res.redirect(`https://${req.headers.host}${req.url}`);
        }
        next();
    });
}

// ==================== Content Security Policy ====================
app.use((req, res, next) => {
  res.setHeader(
    "Content-Security-Policy",
    "default-src 'self'; " +
    "script-src 'self' https://js.stripe.com blob: 'unsafe-eval'; " +
    "style-src 'self' 'unsafe-inline' https://js.stripe.com; " +
    "frame-src https://js.stripe.com https://hooks.stripe.com; " +
    "img-src 'self' data: https://*.stripe.com; " +
    "connect-src 'self' https://api.stripe.com;"
  );
  next();
});



const decoded = Buffer.from(process.env.FB_SERVICE_KEY, 'base64').toString('utf8')
const serviceAccount = JSON.parse(decoded);


// Firebase Admin sdk

// const serviceAccount = require("./firebase-adminsdk-key.json");

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

        const upcomingMealRequestsCollection = db.collection('upcoming_meal_requests');


        const paymentHistoryCollection = db.collection('payment_history');



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



        // GET /meals-by-category?category=Breakfast&limit=8&type=meal
        app.get('/meals-by-category', async (req, res) => {
            try {
                const { category = 'Breakfast', limit = 8, type = 'meal' } = req.query;

                const parsedLimit = parseInt(limit);
                const isAll = parsedLimit === 0;

                const collection = type === 'meal' ? mealsCollection : upcomingMealsCollection;

                const query = category === 'All' ? {} : { category };

                // sort descending by createdAt if field exists, fallback _id descending
                const sortObj = { createdAt: -1 };
                const results = await collection
                    .find(query)
                    .sort(sortObj)
                    .limit(isAll ? 0 : parsedLimit)
                    .toArray();

                // response shape keeping previous structure
                const response = {
                    meals: type === 'meal' ? results : [],
                    upcomingMeals: type === 'upcoming' ? results : [],
                };

                res.status(200).json(response);
            } catch (error) {
                console.error('Error in /meals-by-category:', error);
                res.status(500).json({ error: 'Internal server error' });
            }
        });



        // 🔍 Live Search Meals (title, ingredients, category) from both collections
        app.get('/search-meals', async (req, res) => {
            const query = req.query.q?.toLowerCase();

            if (!query) {
                return res.status(400).send({ message: 'Missing search query' });
            }

            try {
                const searchFilter = {
                    $or: [
                        { title: { $regex: query, $options: 'i' } },
                        { ingredients: { $regex: query, $options: 'i' } },
                        { category: { $regex: query, $options: 'i' } },
                    ],
                };

                // Search from meals, project image too (যেখানে image ফিল্ড আছে ধরে নিচ্ছি)
                const mealResults = await mealsCollection.find(searchFilter)
                    .project({ _id: 1, title: 1, image: 1 }) // image ফিল্ড যুক্ত করো
                    .limit(5)
                    .toArray();

                // Search from upcoming meals, project image too
                const upcomingResults = await upcomingMealsCollection.find(searchFilter)
                    .project({ _id: 1, title: 1, image: 1 }) // image ফিল্ড যুক্ত করো
                    .limit(5)
                    .toArray();

                // Add type to distinguish which is from where
                const formattedResults = [
                    ...mealResults.map(m => ({ ...m, type: 'meal' })),
                    ...upcomingResults.map(m => ({ ...m, type: 'upcoming' })),
                ];

                res.send(formattedResults);
            } catch (error) {
                console.error('❌ Failed to fetch search suggestions:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });




        app.get('/current-user', verifyFBToken, async (req, res) => {
            try {
                // এখানে ক্লায়েন্ট থেকে আলাদা ইমেইল আসবে না
                const email = req.decoded.email.toLowerCase();

                const user = await usersCollection.findOne({ email });
                if (!user) return res.status(404).send({ message: 'User not found' });

                res.send(user);
            } catch (err) {
                console.error('Error in /current-user:', err);
                res.status(500).send({ message: 'Failed to fetch user data', err });
            }
        });



        //         app.get('/current-user', async (req, res) => {
        //   try {
        //     const email = req.query.email;
        //     if (!email) return res.status(400).send({ message: 'Email is required' });

        //     const user = await usersCollection.findOne({ email: email.toLowerCase() });
        //     if (!user) return res.status(404).send({ message: 'User not found' });

        //     res.send(user);
        //   } catch (err) {
        //     console.error('Error in /current-user:', err);
        //     res.status(500).send({ message: 'Failed to fetch user data', err });
        //   }
        // });






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

        app.get('/meals', verifyFBToken, verifyAdmin, async (req, res) => {
            const sortField = req.query.sort || 'likes';
            const sortOrder = req.query.order === 'asc' ? 1 : -1;
            const search = req.query.search || '';
            const page = parseInt(req.query.page) || 1;
            const limit = parseInt(req.query.limit) || 10;
            const skip = (page - 1) * limit;

            const query = search ? { title: { $regex: search, $options: 'i' } } : {};

            try {
                if (sortField === 'category') {
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
                                        branches: Object.entries(categoryOrder).map(([cat, order]) => ({
                                            case: { $eq: ["$category", cat] },
                                            then: order
                                        })),
                                        default: 999
                                    }
                                }
                            }
                        },
                        { $sort: { categoryOrder: sortOrder } },
                        { $skip: skip },
                        { $limit: limit }
                    ];

                    const total = await mealsCollection.countDocuments(query);
                    const meals = await mealsCollection.aggregate(pipeline).toArray();
                    return res.send({ total, data: meals });
                }

                // For likes, reviews_count, postTime
                const sortStage = { [sortField]: sortOrder };

                const total = await mealsCollection.countDocuments(query);
                const meals = await mealsCollection
                    .find(query)
                    .sort(sortStage)
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                res.send({ total, data: meals });
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
                type: 'posted',
                status: status || 'pending',
                requestedAt: new Date().toISOString()
            });

            res.status(201).send({ message: 'Meal requested', insertedId: result.insertedId });
        });



        app.post('/upcoming-meal-requests', verifyFBToken, async (req, res) => {
            const { mealId, userEmail, status } = req.body;

            const exists = await upcomingMealRequestsCollection.findOne({ mealId, userEmail });
            if (exists) return res.status(400).send({ message: 'Already requested' });

            const result = await upcomingMealRequestsCollection.insertOne({
                mealId,
                userEmail,
                type: 'upcoming',
                status: status || 'pending',
                requestedAt: new Date().toISOString()
            });


            res.status(201).send({ message: 'Upcoming meal requested', insertedId: result.insertedId });
        });



        app.post('/meal-reviews', verifyFBToken, async (req, res) => {
            const { mealId, email, name, image, review, rating } = req.body;

            if (!mealId || !review || !email || !name || rating === undefined) {
                return res.status(400).send({ message: 'Missing review info' });
            }

            const reviewDoc = {
                mealId,
                email,
                name,
                image,
                review,
                rating, // Save user rating
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
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 10;
                const search = req.query.search || '';

                const skip = (page - 1) * limit;

                // সার্চ কেসে title ফিল্ডে regex দিয়ে খোঁজ
                const query = search
                    ? { title: { $regex: search, $options: 'i' } }
                    : {};

                const total = await upcomingMealsCollection.countDocuments(query);

                const upcoming = await upcomingMealsCollection
                    .find(query)
                    .sort({ likes: -1 })   // তুমি যেভাবে চেয়েছ তেমন, likes descending
                    .skip(skip)
                    .limit(limit)
                    .toArray();

                res.send({
                    total,
                    data: upcoming,
                });
            } catch (err) {
                res.status(500).send({ message: 'Failed to fetch upcoming meals', err });
            }
        });





        // GET Meals for user and admin both
        app.get('/meals-public', async (req, res) => {
            const { search = '', category, minPrice, maxPrice, page = 1, limit = 6 } = req.query;
            const filter = {};

            if (search) filter.title = { $regex: search, $options: 'i' };
            if (category && category !== 'All') filter.category = category;
            if (minPrice || maxPrice) {
                filter.price = {};
                if (minPrice) filter.price.$gte = Number(minPrice);
                if (maxPrice) filter.price.$lte = Number(maxPrice);
            }

            const skip = (parseInt(page) - 1) * parseInt(limit);
            try {
                const totalCount = await mealsCollection.countDocuments(filter);
                const meals = await mealsCollection
                    .find(filter)
                    .skip(skip)
                    .limit(parseInt(limit))
                    .toArray();

                const isLast = skip + meals.length >= totalCount;
                res.send({ meals, totalCount, isLast });
            } catch (err) {
                res.status(500).send({ message: 'Public meal fetch failed', err });
            }
        });




        // সার্চ, ক্যাটাগরি, প্রাইস রেঞ্জ, পেজিনেশনসহ মিলস রিটার্ন করবে + likes দিয়ে sort করবে
        app.get('/upcoming-meals-public', async (req, res) => {
            const {
                search = '',
                category,
                minPrice,
                maxPrice,
                page = 1,
                limit = 6,
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
                    .sort({ likes: -1, createdAt: -1 })
                    .skip(skip)
                    .limit(parseInt(limit))
                    .toArray();

                const isLast = skip + meals.length >= totalCount;

                res.send({ meals, totalCount, isLast });
            } catch (err) {
                res.status(500).send({ message: 'Public upcoming meals fetch failed', err });
            }
        });




        app.get('/upcoming-meals/:id', verifyFBToken, async (req, res) => {
            const id = req.params.id;

            try {
                const meal = await upcomingMealsCollection.findOne({ _id: new ObjectId(id) });
                if (!meal) return res.status(404).send({ message: 'Upcoming meal not found' });
                res.send(meal);
            } catch (error) {
                res.status(500).send({ message: 'Failed to fetch upcoming meal', error });
            }
        });



        app.delete('/upcoming-meals/:id', verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const id = req.params.id;
                const result = await upcomingMealsCollection.deleteOne({ _id: new ObjectId(id) });
                res.send(result);
            } catch (error) {
                res.status(500).send({ message: 'Failed to delete upcoming meal' });
            }
        });


        // POST: Add a review to an upcoming meal
        app.post('/upcoming-meal-reviews', verifyFBToken, async (req, res) => {
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
                createdAt: new Date().toISOString(),
            };

            try {
                const result = await upcomingMealsCollection.updateOne(
                    { _id: new ObjectId(mealId) },
                    {
                        $push: { reviews: reviewDoc },
                        $inc: { reviews_count: 1 },
                    }
                );

                if (result.modifiedCount > 0) {
                    res.send({ message: 'Review added', success: true });
                } else {
                    res.status(404).send({ message: 'Upcoming meal not found' });
                }
            } catch (error) {
                console.error('Failed to add upcoming meal review:', error);
                res.status(500).send({ message: 'Failed to add review', error });
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


        // PATCH: Update rating of upcoming meal
        app.patch('/upcoming-meals/rating/:id', verifyFBToken, async (req, res) => {
            const mealId = req.params.id;
            const { rating } = req.body;

            if (!rating || rating < 1 || rating > 5) {
                return res.status(400).send({ message: 'Invalid rating value' });
            }

            try {
                const meal = await upcomingMealsCollection.findOne({ _id: new ObjectId(mealId) });
                if (!meal) {
                    return res.status(404).send({ message: 'Meal not found' });
                }

                // যদি ডাটাবেজে rating না থাকে, নতুন করে সেট করবে, নাহলে আপডেট করবে
                const update = { $set: { rating: rating } };

                const result = await upcomingMealsCollection.updateOne(
                    { _id: new ObjectId(mealId) },
                    update
                );

                if (result.modifiedCount > 0) {
                    res.send({ message: 'Rating updated', success: true });
                } else {
                    res.status(500).send({ message: 'Failed to update rating' });
                }
            } catch (err) {
                res.status(500).send({ message: 'Server error', error: err });
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


        app.get('/meal-requests', verifyFBToken, async (req, res) => {
            const userEmail = req.query.userEmail;

            if (!userEmail) {
                return res.status(400).send({ message: 'Missing userEmail' });
            }

            if (req.decoded.email !== userEmail) {
                return res.status(403).send({ message: 'Forbidden: You can only access your own requests' });
            }

            try {
                const requests = await mealRequestsCollection
                    .find({ userEmail })
                    .sort({ requestedAt: -1 })
                    .toArray();

                res.send(requests);
            } catch (error) {
                console.error('Failed to fetch meal requests:', error);
                res.status(500).send({ message: 'Server error while fetching meal requests' });
            }
        });



        app.get('/upcoming-meal-requests', verifyFBToken, async (req, res) => {
            const userEmail = req.query.userEmail;

            if (!userEmail) {
                return res.status(400).send({ message: 'Missing userEmail' });
            }

            if (req.decoded.email !== userEmail) {
                return res.status(403).send({ message: 'Forbidden: You can only access your own requests' });
            }

            const requests = await upcomingMealRequestsCollection
                .find({ userEmail })
                .sort({ requestedAt: -1 })
                .toArray();


            res.send(requests);
        });






        app.delete('/upcoming-meal-requests/:id', verifyFBToken, async (req, res) => {
            const id = req.params.id;

            const request = await upcomingMealRequestsCollection.findOne({ _id: new ObjectId(id) });

            if (!request) {
                return res.status(404).send({ message: 'Meal request not found' });
            }

            if (req.decoded.email !== request.userEmail) {
                return res.status(403).send({ message: 'Forbidden: You can only delete your own upcoming meal requests' });
            }

            const result = await upcomingMealRequestsCollection.deleteOne({ _id: new ObjectId(id) });


            res.send({ success: result.deletedCount > 0 });
        });




        // puslish upcoming meals to main meals collection
        app.post('/publish-meal/:id', verifyFBToken, verifyAdmin, async (req, res) => {
            const mealId = req.params.id;
            try {
                const upcomingMeal = await db.collection('upcoming_meals').findOne({ _id: new ObjectId(mealId) });
                if (!upcomingMeal) {
                    return res.status(404).send({ message: 'Meal not found' });
                }

                if ((upcomingMeal.likes || 0) < 10) {
                    return res.status(400).send({ message: 'At least 10 likes required to publish.' });
                }

                // Insert into main meals collection
                await db.collection('meals').insertOne({
                    ...upcomingMeal,
                    rating: 0,
                    reviews_count: 0,
                    likes: upcomingMeal.likes || 0,
                    publishedAt: new Date().toISOString()
                });

                // Remove from upcoming
                await db.collection('upcoming_meals').deleteOne({ _id: new ObjectId(mealId) });

                res.send({ message: 'Meal published successfully' });
            } catch (error) {
                res.status(500).send({ message: 'Failed to publish meal', error: error.message });
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



        app.delete('/meal-requests/:id', verifyFBToken, async (req, res) => {
            const id = req.params.id;

            try {
                const request = await mealRequestsCollection.findOne({ _id: new ObjectId(id) });

                if (!request) {
                    return res.status(404).send({ message: 'Meal request not found' });
                }

                // টোকেনের ইউজার ইমেইল চেক করো যাতে নিজেই শুধু ডিলেট করতে পারে
                if (req.decoded.email !== request.userEmail) {
                    return res.status(403).send({ message: 'Forbidden: You can only delete your own requests' });
                }

                const result = await mealRequestsCollection.deleteOne({ _id: new ObjectId(id) });

                if (result.deletedCount === 1) {
                    res.send({ success: true, message: 'Meal request cancelled successfully' });
                } else {
                    res.status(500).send({ success: false, message: 'Failed to cancel meal request' });
                }
            } catch (error) {
                console.error('Error deleting meal request:', error);
                res.status(500).send({ message: 'Internal Server Error' });
            }
        });




        // checkout apis
        app.post('/create-payment-intent', verifyFBToken, async (req, res) => {
            const { packageName, price } = req.body;

            if (!price) {
                return res.status(400).send({ message: 'Missing price' });
            }

            try {
                const paymentIntent = await stripe.paymentIntents.create({
                    amount: price * 100,
                    currency: "usd",
                    payment_method_types: ["card"],
                });

                res.send({ clientSecret: paymentIntent.client_secret });
            } catch (error) {
                console.error('Stripe error:', error);
                res.status(500).send({ error: 'Payment intent creation failed' });
            }
        });



        app.post('/payments', verifyFBToken, async (req, res) => {
            const { email, packageName, transactionId, price } = req.body;

            if (!email || !packageName || !transactionId || !price) {
                return res.status(400).send({ message: 'Missing required payment fields' });
            }

            try {
                const user = await usersCollection.findOne({ email });

                if (!user) {
                    return res.status(404).send({ message: 'User not found' });
                }

                const paidAt = new Date().toISOString();

                // Insert into payment_history collection
                const paymentHistoryDoc = {
                    userId: user._id,
                    name: user.name,
                    email: user.email,
                    photo: user.photo,
                    badge: packageName,
                    price,
                    transactionId,
                    packageName,
                    paidAt,
                    gateway: "Stripe",
                    method: "Card",
                    currency: "USD"
                };

                await paymentHistoryCollection.insertOne(paymentHistoryDoc);

                // Update user's subscription & badge
                await usersCollection.updateOne(
                    { email },
                    {
                        $set: {
                            subscription: packageName,
                            badge: packageName
                        }
                    }
                );

                res.send({ message: 'Payment saved successfully', success: true });
            } catch (err) {
                console.error('❌ Error saving payment:', err);
                res.status(500).send({ message: 'Payment saving failed', error: err.message });
            }
        });





        // ✅ Get payment history of a user
        app.get('/my-payments', verifyFBToken, async (req, res) => {
            const email = req.query.email;

            if (!email || req.decoded.email !== email) {
                return res.status(403).send({ message: 'Forbidden access' });
            }

            try {
                const payments = await paymentHistoryCollection
                    .find({ email })
                    .sort({ paidAt: -1 })
                    .toArray();

                res.send(payments);
            } catch (error) {
                console.error('❌ Payment history fetch error:', error);
                res.status(500).send({ message: 'Failed to fetch payment history' });
            }
        });





        app.get('/admin/all-reviews', verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 10;
                const skip = (page - 1) * limit;

                const meals = await mealsCollection.find({
                    reviews: { $exists: true, $ne: [] }
                }).toArray();

                const upcomingMeals = await upcomingMealsCollection.find({
                    reviews: { $exists: true, $ne: [] }
                }).toArray();

                const allReviews = [];

                const processReviews = (mealList, source) => {
                    mealList.forEach(meal => {
                        if (Array.isArray(meal.reviews)) {
                            meal.reviews.forEach(review => {
                                allReviews.push({
                                    _id: new ObjectId(),
                                    mealId: meal._id,
                                    mealTitle: meal.title,
                                    from: source,
                                    reviewText: review.review || '',
                                    reviewerName: review.name || '',
                                    reviewerEmail: review.email || '',
                                    reviewerImage: review.image || '',
                                    likes: meal.likes || 0,
                                    reviews_count: meal.reviews_count || 0,
                                    createdAt: review.createdAt || meal.postTime || meal.createdAt
                                });
                            });
                        }
                    });
                };

                processReviews(meals, "meals");
                processReviews(upcomingMeals, "upcoming_meals");

                // Sort newest first
                allReviews.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

                const total = allReviews.length;
                const paginated = allReviews.slice(skip, skip + limit);

                res.send({
                    page,
                    limit,
                    total,
                    totalPages: Math.ceil(total / limit),
                    reviews: paginated
                });
            } catch (err) {
                res.status(500).send({ message: 'Something went wrong', error: err.message });
            }
        });



        // Delete a review by ID
        app.delete('/admin/reviews/:mealId/:source/:reviewerEmail', verifyFBToken, verifyAdmin, async (req, res) => {
            const { mealId, source, reviewerEmail } = req.params;

            const collection = source === 'meals'
                ? db.collection('meals')
                : db.collection('upcoming_meals');

            const result = await collection.updateOne(
                { _id: new ObjectId(mealId) },
                { $pull: { reviews: { email: reviewerEmail } } }
            );

            res.send(result);
        });








        // GET all meal requests (with pagination + search + merged)
        app.get('/admin/all-meal-requests', verifyFBToken, verifyAdmin, async (req, res) => {
            try {
                const page = parseInt(req.query.page) || 1;
                const limit = parseInt(req.query.limit) || 10;
                const search = req.query.search || '';
                const skip = (page - 1) * limit;
                const regex = new RegExp(search, 'i');

                // Fetch from both collections with filtering by userEmail or status
                const mealRequests = await mealRequestsCollection.aggregate([
                    {
                        $addFields: {
                            mealIdObj: { $toObjectId: "$mealId" } // 👈 convert string to ObjectId
                        }
                    },
                    {
                        $lookup: {
                            from: "meals",
                            localField: "mealIdObj",
                            foreignField: "_id",
                            as: "mealInfo"
                        }
                    },
                    { $unwind: "$mealInfo" },
                    {
                        $addFields: {
                            mealTitle: "$mealInfo.title"
                        }
                    },
                    {
                        $match: {
                            $or: [
                                { userEmail: { $regex: regex } },
                                { status: { $regex: regex } }
                            ]
                        }
                    },
                    { $project: { mealInfo: 0, mealIdObj: 0 } }
                ]).toArray();


                const upcomingRequests = await upcomingMealRequestsCollection.aggregate([
                    {
                        $addFields: {
                            mealIdObj: { $toObjectId: "$mealId" }
                        }
                    },
                    {
                        $lookup: {
                            from: "upcoming_meals",
                            localField: "mealIdObj",
                            foreignField: "_id",
                            as: "mealInfo"
                        }
                    },
                    { $unwind: "$mealInfo" },
                    {
                        $addFields: {
                            mealTitle: "$mealInfo.title"
                        }
                    },
                    {
                        $match: {
                            $or: [
                                { userEmail: { $regex: regex } },
                                { status: { $regex: regex } }
                            ]
                        }
                    },
                    { $project: { mealInfo: 0, mealIdObj: 0 } }
                ]).toArray();


                // Add source field for identifying source collection
                const merged = [
                    ...mealRequests.map(req => ({
                        ...req,
                        from: 'meals'
                    })),
                    ...upcomingRequests.map(req => ({
                        ...req,
                        from: 'upcoming_meals'
                    }))
                ];

                // Sort newest first
                merged.sort((a, b) => new Date(b.requestedAt) - new Date(a.requestedAt));

                // Pagination
                const total = merged.length;
                const totalPages = Math.ceil(total / limit);
                const paginated = merged.slice(skip, skip + limit);

                // Response
                res.send({
                    page,
                    limit,
                    total,
                    totalPages,
                    requests: paginated
                });

            } catch (err) {
                console.error('❌ Error fetching meal requests:', err);
                res.status(500).send({ message: 'Failed to fetch meal requests', error: err.message });
            }
        });




        app.patch('/admin/serve-meal-request/:source/:id', verifyFBToken, verifyAdmin, async (req, res) => {
            const { source, id } = req.params;

            const collection =
                source === 'meals' ? mealRequestsCollection : upcomingMealRequestsCollection;

            try {
                const result = await collection.updateOne(
                    { _id: new ObjectId(id) },
                    {
                        $set: {
                            status: 'delivered',
                            servedAt: new Date().toISOString()
                        }
                    }
                );

                if (result.modifiedCount === 0) {
                    return res.status(404).send({ message: 'Request not found or already served' });
                }

                res.send({ success: true, message: 'Meal served successfully' });
            } catch (error) {
                console.error('❌ Error serving meal:', error);
                res.status(500).send({ message: 'Failed to serve meal', error: error.message });
            }
        });






        app.get('/my-reviews', verifyFBToken, async (req, res) => {
            const email = req.query.email;

            if (!email || req.decoded.email !== email) {
                return res.status(403).send({ message: 'Forbidden Access' });
            }

            try {
                const meals = await mealsCollection.find({
                    reviews: { $elemMatch: { email } }
                }).toArray();

                const upcomingMeals = await upcomingMealsCollection.find({
                    reviews: { $elemMatch: { email } }
                }).toArray();

                const myReviews = [];

                const extractReviews = (mealList, from) => {
                    mealList.forEach(meal => {
                        meal.reviews?.forEach(review => {
                            if (review.email === email) {
                                myReviews.push({
                                    mealId: meal._id,
                                    mealTitle: meal.title,
                                    mealImage: meal.image,
                                    from, // 'meals' or 'upcoming_meals'
                                    reviewText: review.review,
                                    createdAt: review.createdAt,
                                    reviewerName: review.name,
                                    reviewerImage: review.image,
                                });
                            }
                        });
                    });
                };

                extractReviews(meals, 'meals');
                extractReviews(upcomingMeals, 'upcoming_meals');

                myReviews.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

                res.send(myReviews);
            } catch (error) {
                console.error('❌ Error fetching user reviews:', error);
                res.status(500).send({ message: 'Failed to fetch your reviews', error: error.message });
            }
        });






        app.delete('/my-reviews/:mealId/:from', verifyFBToken, async (req, res) => {
            const email = req.decoded.email;
            const { mealId, from } = req.params;

            const collection = from === 'meals' ? mealsCollection : upcomingMealsCollection;

            try {
                const result = await collection.updateOne(
                    { _id: new ObjectId(mealId) },
                    {
                        $pull: { reviews: { email } },
                        $inc: { reviews_count: -1 }
                    }
                );

                res.send({ success: result.modifiedCount > 0 });
            } catch (error) {
                console.error('❌ Error deleting review:', error);
                res.status(500).send({ message: 'Failed to delete review', error: error.message });
            }
        });






        app.patch('/my-reviews/:mealId/:from', verifyFBToken, async (req, res) => {
            const email = req.decoded.email;
            const { mealId, from } = req.params;
            const { newReviewText } = req.body;

            const collection = from === 'meals' ? mealsCollection : upcomingMealsCollection;

            try {
                const result = await collection.updateOne(
                    {
                        _id: new ObjectId(mealId),
                        "reviews.email": email
                    },
                    {
                        $set: { "reviews.$.review": newReviewText }
                    }
                );

                res.send({ success: result.modifiedCount > 0 });
            } catch (error) {
                console.error('❌ Error updating review:', error);
                res.status(500).send({ message: 'Failed to update review', error: error.message });
            }
        });



// GET: /admin-dashboard
app.get('/admin-dashboard', verifyFBToken, verifyAdmin, async (req, res) => {
    const { email } = req.query;

    try {
        const now = new Date();
        const todayStart = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const todayEnd = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 1);

        // Total meals posted by this admin
        const totalMeals = await mealsCollection.countDocuments({ distributorEmail: email });

        // Global counts
        const totalUsers = await usersCollection.estimatedDocumentCount();
        const pendingRequests = await mealRequestsCollection.countDocuments({ status: 'pending' });
        const pendingUpcomingRequests = await upcomingMealRequestsCollection.countDocuments({ status: 'pending' });
        const upcomingMealsCount = await upcomingMealsCollection.estimatedDocumentCount();

        // Today’s new users
        const todayUsers = await usersCollection.aggregate([
            {
                $addFields: {
                    createdAtDate: {
                        $cond: [
                            { $ifNull: ["$created_At", false] },
                            { $toDate: "$created_At" },
                            new Date(0)
                        ]
                    }
                }
            },
            {
                $match: {
                    createdAtDate: {
                        $gte: todayStart,
                        $lt: todayEnd
                    }
                }
            },
            { $count: "count" }
        ]).toArray();
        const todayUserCount = todayUsers[0]?.count || 0;

        // Today’s meal requests
        const todayMealRequestsAgg = await mealRequestsCollection.aggregate([
            {
                $addFields: {
                    reqDate: { $cond: [{ $ifNull: ["$requestedAt", false] }, { $toDate: "$requestedAt" }, new Date(0)] }
                }
            },
            { $match: { reqDate: { $gte: todayStart, $lt: todayEnd } } },
            { $count: "count" }
        ]).toArray();
        const todayMealRequests = todayMealRequestsAgg[0]?.count || 0;

        // Today’s upcoming meal requests
        const todayUpcomingAgg = await upcomingMealRequestsCollection.aggregate([
            {
                $addFields: {
                    reqDate: { $cond: [{ $ifNull: ["$requestedAt", false] }, { $toDate: "$requestedAt" }, new Date(0)] }
                }
            },
            { $match: { reqDate: { $gte: todayStart, $lt: todayEnd } } },
            { $count: "count" }
        ]).toArray();
        const todayUpcomingMealRequests = todayUpcomingAgg[0]?.count || 0;

        // Role statistics
        const userRoles = await usersCollection.aggregate([
            { $group: { _id: "$role", count: { $sum: 1 } } }
        ]).toArray();

        // Most active meal distributor
        const mostMealsAddedBy = await mealsCollection.aggregate([
            { $group: { _id: "$distributorEmail", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
            { $limit: 1 }
        ]).toArray();

        // Meal counts by month (using postTime)
        const mealCountsPerMonth = await mealsCollection.aggregate([
            {
                $addFields: {
                    postDate: { $cond: [{ $ifNull: ["$postTime", false] }, { $toDate: "$postTime" }, new Date(0)] }
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: "$postDate" },
                        month: { $month: "$postDate" }
                    },
                    count: { $sum: 1 }
                }
            },
            { $sort: { "_id.year": 1, "_id.month": 1 } }
        ]).toArray();

        // Total reviews (meals + upcoming meals)
        const totalReviewsMeals = await mealsCollection.aggregate([
            { $project: { count: { $size: { $ifNull: ["$reviews", []] } } } },
            { $group: { _id: null, total: { $sum: "$count" } } }
        ]).toArray();

        const totalReviewsUpcoming = await upcomingMealsCollection.aggregate([
            { $project: { count: { $size: { $ifNull: ["$reviews", []] } } } },
            { $group: { _id: null, total: { $sum: "$count" } } }
        ]).toArray();

        const totalReviews = (totalReviewsMeals[0]?.total || 0) + (totalReviewsUpcoming[0]?.total || 0);

        // Last 3 pending meal requests
        const last3PendingMealRequests = await mealRequestsCollection
            .find({ status: 'pending' })
            .sort({ requestedAt: -1 })
            .limit(3)
            .toArray();

        const last3PendingUpcomingRequests = await upcomingMealRequestsCollection
            .find({ status: 'pending' })
            .sort({ requestedAt: -1 })
            .limit(3)
            .toArray();

        // Latest 2 users
        const latest2Users = await usersCollection
            .find({})
            .sort({ created_At: -1 })
            .limit(2)
            .project({ name: 1, email: 1, photo: 1 })
            .toArray();

        res.send({
            totalMeals,
            totalUsers,
            pendingRequests,
            pendingUpcomingRequests,
            upcomingMealsCount,
            todayUserCount,
            todayMealRequests,
            todayUpcomingMealRequests,
            userRoles,
            mostMealsAddedBy: mostMealsAddedBy[0] || null,
            mealCountsPerMonth,
            totalReviews,
            last3PendingMealRequests,
            last3PendingUpcomingRequests,
            latest2Users
        });

    } catch (err) {
        console.error("Admin Dashboard Error:", err);
        res.status(500).send({ message: 'Dashboard load failed' });
    }
});







        app.get('/user-dashboard', verifyFBToken, async (req, res) => {
            const email = req.query.email;

            if (!email || req.decoded.email !== email) {
                return res.status(403).send({ message: 'Forbidden access' });
            }

            try {
                const user = await usersCollection.findOne({ email });

                // ১. Badge Info & Subscription
                const badge = user?.badge || 'Bronze';
                const subscription = user?.subscription || 'Bronze';

                // ২. Counts
                const postedCount = await mealRequestsCollection.countDocuments({ userEmail: email });
                const upcomingCount = await upcomingMealRequestsCollection.countDocuments({ userEmail: email });
                const requestedMealCount = postedCount + upcomingCount;

                const totalReviewsMeals = await mealsCollection.countDocuments({ reviews: { $elemMatch: { email } } });
                const totalReviewsUpcoming = await upcomingMealsCollection.countDocuments({ reviews: { $elemMatch: { email } } });
                const totalReviews = totalReviewsMeals + totalReviewsUpcoming;

                const totalPayments = await paymentHistoryCollection.countDocuments({ email });

                // ৩. Recent Requested Meals
                const postedMeals = await mealRequestsCollection
                    .find({ userEmail: email })
                    .sort({ requestedAt: -1 })
                    .limit(3)
                    .toArray();

                const upcomingMeals = await upcomingMealRequestsCollection
                    .find({ userEmail: email })
                    .sort({ requestedAt: -1 })
                    .limit(3)
                    .toArray();

                // Meal titles fetch
                const postedMealIds = postedMeals.map(m => new ObjectId(m.mealId));
                const upcomingMealIds = upcomingMeals.map(m => new ObjectId(m.mealId));

                const postedMealDocs = await mealsCollection
                    .find({ _id: { $in: postedMealIds } })
                    .project({ _id: 1, title: 1 })
                    .toArray();

                const upcomingMealDocs = await upcomingMealsCollection
                    .find({ _id: { $in: upcomingMealIds } })
                    .project({ _id: 1, title: 1 })
                    .toArray();

                const postedMealMap = Object.fromEntries(postedMealDocs.map(m => [m._id.toString(), m.title]));
                const upcomingMealMap = Object.fromEntries(upcomingMealDocs.map(m => [m._id.toString(), m.title]));

                // Combine and format
                const recentRequestedMeals = [
                    ...postedMeals.map(m => ({
                        mealId: m.mealId,
                        title: postedMealMap[m.mealId] || 'Unknown Meal',
                        type: 'posted',
                        status: m.status,
                        requestedAt: m.requestedAt,
                    })),
                    ...upcomingMeals.map(m => ({
                        mealId: m.mealId,
                        title: upcomingMealMap[m.mealId] || 'Unknown Upcoming Meal',
                        type: 'upcoming',
                        status: m.status,
                        requestedAt: m.requestedAt,
                    })),
                ].sort((a, b) => new Date(b.requestedAt) - new Date(a.requestedAt)).slice(0, 3);

                // ৪. Recent Reviews
                const extractRecentReviews = (meals, from) =>
                    meals.flatMap(meal =>
                        (meal.reviews || [])
                            .filter(r => r.email === email)
                            .map(r => ({
                                mealId: meal._id,
                                mealTitle: meal.title,
                                from,
                                reviewText: r.review,
                                createdAt: r.createdAt
                            }))
                    );

                const reviewedMeals = await mealsCollection
                    .find({ reviews: { $elemMatch: { email } } })
                    .limit(10).toArray();

                const reviewedUpcomingMeals = await upcomingMealsCollection
                    .find({ reviews: { $elemMatch: { email } } })
                    .limit(10).toArray();

                let allReviews = [
                    ...extractRecentReviews(reviewedMeals, 'meals'),
                    ...extractRecentReviews(reviewedUpcomingMeals, 'upcoming_meals'),
                ];

                allReviews.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
                const recentReviews = allReviews.slice(0, 2);

                // Final Response
                res.send({
                    badge,
                    subscription,
                    requestedMealCount,
                    totalReviews,
                    totalPayments,
                    recentRequestedMeals,
                    recentReviews,
                    userInfo: {
                        name: user?.name || 'User',
                        email: user?.email,
                        photo: user?.photo || '',
                    }
                });

            } catch (error) {
                console.error('❌ Dashboard Load Error:', error);
                res.status(500).send({ message: 'Failed to load dashboard data' });
            }
        });


        // routes/meals.js
        app.get('/meals-popular', async (req, res) => {
            try {
                const popularMeals = await mealsCollection.find({})
                    .sort({ likes: -1, ordersCount: -1, reviewsCount: -1 })
                    .limit(6)
                    .project({
                        title: 1,
                        image: 1,
                        price: 1,
                        likes: 1,
                        reviewsCount: 1,
                        distributorName: 1
                    })
                    .toArray();

                res.status(200).json(popularMeals);
            } catch (error) {
                console.error('❌ Error fetching popular meals:', error.message);
                res.status(500).json({ error: 'Failed to fetch popular meals' });
            }
        });



        // routes/reviews.js
        app.get('/reviews-featured', async (req, res) => {
            try {
                const mealsFeatured = await mealsCollection.aggregate([
                    { $unwind: "$reviews" },
                    { $replaceRoot: { newRoot: "$reviews" } },
                    { $sort: { createdAt: -1 } },
                ]).toArray();

                const upcomingFeatured = await upcomingMealsCollection.aggregate([
                    { $unwind: "$reviews" },
                    { $replaceRoot: { newRoot: "$reviews" } },
                    { $sort: { createdAt: -1 } },
                ]).toArray();


                const combinedReviews = [...mealsFeatured, ...upcomingFeatured];

                const topReviews = combinedReviews
                    .filter(r => r.review && r.review.trim() !== "")
                    .sort((a, b) => (b.likes || 0) - (a.likes || 0) || new Date(b.createdAt) - new Date(a.createdAt))
                    .slice(0, 5);

                res.status(200).json(topReviews);
            } catch (error) {
                console.error('❌ Error fetching featured reviews:', error);
                res.status(500).json({ error: 'Failed to fetch featured reviews' });
            }
        });



        // routes/faqs.js
        app.get('/faqs', async (req, res) => {
            try {
                const faqs = await db.collection('faqs')
                    .find({})
                    .sort({ createdAt: -1 })
                    .limit(10)
                    .project({ question: 1, answer: 1 })
                    .toArray();

                res.status(200).json(faqs);
            } catch (error) {
                console.error('❌ Error fetching FAQs:', error.message);
                res.status(500).json({ error: 'Failed to fetch FAQs' });
            }
        });

        // // Send a ping to confirm a successful connection
        // await client.db("admin").command({ ping: 1 });
        // console.log("Pinged your deployment. You successfully connected to MongoDB!");

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