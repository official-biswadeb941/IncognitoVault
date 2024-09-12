import redis

# Define the Redis URLs
redis_url_1 = "rediss://default:AVNS_UmG_umqW4eQrknqH_M0@incogito-vault-caching-incognitovault.k.aivencloud.com:26836"
redis_url_2 = "rediss://default:AVNS_bGNX3CC845HWrgTqeIV@incogito-vault-caching-incognito-vault.k.aivencloud.com:24421"

# Connect to the first Redis instance
r1 = redis.Redis.from_url(redis_url_1)

# Connect to the second Redis instance
r2 = redis.Redis.from_url(redis_url_2)

# Flush the databases
r1.flushdb()
r2.flushdb()

print("Both Redis instances have been flushed.")
