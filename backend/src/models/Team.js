// backend/src/models/Team.js
import mongoose from 'mongoose';

const UserCredSchema = new mongoose.Schema(
  {
    userId:       { type: String, default: '', trim: true },
    passwordHash: { type: String, default: '', trim: true },
  },
  { _id: false }
);

const SESchema = new mongoose.Schema(
  {
    name:  { type: String, trim: true },
    users: { type: [UserCredSchema], default: [{ userId: '', passwordHash: '' }] },
  },
  { _id: false }
);

const SMSchema = new mongoose.Schema(
  {
    name:  { type: String, trim: true },
    users: { type: [UserCredSchema], default: [{ userId: '', passwordHash: '' }] },
    ses:   { type: [SESchema], default: [] },
  },
  { _id: false }
);

const RMSchema = new mongoose.Schema(
  {
    name:  { type: String, trim: true },
    users: { type: [UserCredSchema], default: [{ userId: '', passwordHash: '' }] },
    sms:   { type: [SMSchema], default: [] },
  },
  { _id: false }
);

const ZoneSchema = new mongoose.Schema(
  {
    name:  { type: String, trim: true },
    users: { type: [UserCredSchema], default: [{ userId: '', passwordHash: '' }] },
    rms:   { type: [RMSchema], default: [] },
  },
  { _id: false }
);

const TeamSchema = new mongoose.Schema(
  {
    // The admin who owns/maintains this team tree
    ownerUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true, unique: true },
    team:        { type: [ZoneSchema], default: [] },
  },
  { timestamps: true }
);

export default mongoose.model('Team', TeamSchema);
