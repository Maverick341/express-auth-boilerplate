import mongoose, { Schema } from "mongoose";

const vectorIndexMetadataSchema = new Schema({
    documentId: {
        type: String,
        required: true,
        index: true,
    },
    provider: {
        type: String,
        required: true,
        enum: ['qdrant', 'pinecone', 'weaviate', 'milvus'],
    },
    collectionName: {
        type: String,
        required: true,
        index: true,
    },
    indexedAt: {
        type: Date,
        default: Date.now,
        index: true,
    },
    chunkCount: {
        type: Number,
        default: 0,
    },
    embeddingModel: {
        type: String,
        default: 'openai-embedding-3-small',
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    },
}, { timestamps: true });

vectorIndexMetadataSchema.index({ documentId: 1, provider: 1 });

export const VectorIndexMetadata = mongoose.model('VectorIndexMetadata', vectorIndexMetadataSchema);
