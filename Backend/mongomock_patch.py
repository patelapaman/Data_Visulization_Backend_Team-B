import mongomock
import pymongo
pymongo.MongoClient = mongomock.MongoClient
