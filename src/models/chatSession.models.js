import mongoose, { Schema } from "mongoose";

const chatSessionSchema = new Schema({
    chatId: {
        type: String,
        required: true,
        unique: true,
        index: true,
    },
    title: {
        type: String,
        required: true,
        trim: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: true,
    },
    messageCount: {
        type: Number,
        default: 0,
    },
    updatedAt: {
        type: Date,
        default: Date.now,
    },
}, { timestamps: true });

export const ChatSession = mongoose.model('ChatSession', chatSessionSchema);
