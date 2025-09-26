const {createClient} = require('redis');

const connectRedis = async () => {
    let client = null;
    client = createClient({
    url: process.env.REDIS_URL
    });
    await client.connect().then((res) => {
        console.log("Redis connected successfully");    
    }).catch((err) => {
        console.log("Redis connection error: ", err);
        process.exit(1);
    });
    return client
}

module.exports = {
    "redisClient": connectRedis
}