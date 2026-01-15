import mongoose, { Schema } from "mongoose";

const graphMetadataSchema = new Schema({
    documentId: {
        type: String,
        required: true,
        index: true,
    },
    entityCount: {
        type: Number,
        default: 0,
    },
    relationCount: {
        type: Number,
        default: 0,
    },
    builtAt: {
        type: Date,
        default: Date.now,
        index: true,
    },
    graphStatus: {
        type: String,
        enum: ['pending', 'building', 'complete', 'failed'],
        default: 'pending',
    },
    errorMessage: {
        type: String,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    },
}, { timestamps: true });

export const GraphMetadata = mongoose.model('GraphMetadata', graphMetadataSchema);
