import mongoose, { Schema } from "mongoose";

const chatMessageSchema = new Schema({
    messageId: {
        type: String,
        required: true,
        unique: true,
        index: true,
    },
    chatId: {
        type: String,
        required: true,
        index: true,
    },
    role: {
        type: String,
        enum: ['user', 'assistant', 'system'],
        required: true,
    },
    content: {
        type: String,
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
        index: true,
    },
    metadata: {
        tokens: Number,
        model: String,
    },
}, { timestamps: true });

chatMessageSchema.index({ chatId: 1, createdAt: -1 });

export const ChatMessage = mongoose.model('ChatMessage', chatMessageSchema);
