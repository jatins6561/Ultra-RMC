// backend/src/models/Record.js
import mongoose from 'mongoose';

const { Schema } = mongoose;

/* ------------------------ Sub-schemas ------------------------ */
const MaterialSchema = new Schema(
  {
    name: { type: String, required: true },
    rate: { type: Number, default: 0 },
    mix:  { type: Number, default: 0 },
    cost: { type: Number, default: 0 },
  },
  { _id: false }
);

const TMSchema = new Schema(
  {
    L1:Number, L2:Number, L3:Number, L4:Number, L5:Number,
    L6:Number, L7:Number, L8:Number, L9:Number,
  },
  { _id: false }
);

const PricingSchema = new Schema(
  {
    C1:Number, C2:Number, C3:Number, C4:Number, C5:Number, C6:Number, C7:Number,
    C8:Number, C9:Number, C10:Number, C11:Number, C12:Number, C13:Number, C14:Number,
    C15:Number, C16:Number, C17:Number,
  },
  { _id: false }
);

/** Who created the record (from JWT at save time) */
const CreatedBySchema = new Schema(
  {
    userId: String,        // JWT id (e.g., user _id or team:<TeamDocId>)
    emailOrId: String,     // email (admin) or team userId (zone/rm/sm/se)
    role: String,          // admin | zone | rm | sm | se | user
    designation: String,   // Zonal Head / Regional Manager / Sales Manager / Sales Executive / Admin / User
    name: String,          // derived from email/id: e.g., "vipin"
  },
  { _id: false }
);

/* --------------------------- Main schema --------------------------- */
const RecordSchema = new Schema(
  {
    // We use Mongo's _id; frontend can read it via virtual p_id
    date: { type: Date, default: Date.now },

    // header chips
    project: String,
    qty: Number,
    grade: String,
    plant: String,
    site:  String,
    grade_record: String,
    mix_version:  String,

    // sections
    pump: { P1: { type: Number, default: 200 } },
    tm: TMSchema,
    pricing: PricingSchema,
    materials: { type: [MaterialSchema], default: [] },

    // workflow
    status: {
      type: String,
      enum: ['draft', 'submitted'],
      default: 'draft',
      index: true,
    },

    // audit
    createdBy: CreatedBySchema,
  },
  {
    timestamps: true,
    toJSON:   { virtuals: true },
    toObject: { virtuals: true },
  }
);

/* Virtual: expose _id as p_id so existing UI using r.p_id keeps working */
RecordSchema.virtual('p_id').get(function () {
  return this._id?.toString();
});

export default mongoose.model('Record', RecordSchema);
