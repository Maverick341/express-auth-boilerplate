import mongoose, { Schema } from "mongoose";

const documentSchema = new Schema({
    title: {
        type: String,
        required: true,
    },
    filename: {
        type: String,
        required: true,
    },
    status: {
        type: String,
        required: true,
    },
    createdAt: {
        type: Date,
        required: true,
    },
});

export const Document = mongoose.model('Document', documentSchema);
