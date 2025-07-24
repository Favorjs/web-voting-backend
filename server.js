require('dotenv').config();
const express = require('express');
const session = require('express-session');
const Sequelize = require('sequelize');
const bodyParser = require('body-parser');

const bcrypt = require('bcryptjs');
const { Op,DataTypes } = require('sequelize');
const cors = require('cors');
const app = express();

// CORS middleware at the very top
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:5173');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// BODY PARSER before any routes or session
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
const http = require('http');
const { Server } = require('socket.io');
const server = http.createServer(app);

const pgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');

// Add this after your Sequelize initialization

const requireAuth = (req, res, next) => {
  //console.log('Session debug:', req.session); // For debugging
  if (!req.session?.userId) {
    return res.status(401).json({ 
      success: false,
      error: 'Not authenticated' 
      
});
  }
  next();
};
const io = new Server(server, {
  cors: {
    origin: "http://localhost:5173",
    methods: ["GET", "POST"]
  }
  
});


// Database setup (PostgreSQL)
// PostgreSQL connection pool for session store
// Build database configuration
const pgConfig = process.env.DATABASE_URL
  ? {
      connectionString: process.env.DATABASE_URL,
      ssl: process.env.DB_SSL === 'false' ? false : { rejectUnauthorized: false }
    }
  : {
      user: process.env.DB_USER || 'postgres',
      password: process.env.DB_PASSWORD || '',
      host: process.env.DB_HOST || 'localhost',
      port: process.env.DB_PORT || 5432,
      database: process.env.DB_NAME || 'e-voting',
      ssl: process.env.DB_SSL === 'true' ? { rejectUnauthorized: false } : false
    };

const pool = new Pool(pgConfig);

const sequelize = process.env.DATABASE_URL
  ? new Sequelize(process.env.DATABASE_URL, {
      dialect: 'postgres',
      protocol: 'postgres',
      logging: false,
      dialectOptions: {
        ssl: process.env.DB_SSL === 'false' ? false : {
          require: true,
          rejectUnauthorized: false
        }
      }
    })
  : new Sequelize(
      process.env.DB_NAME || 'e-voting',
      process.env.DB_USER || 'postgres',
      process.env.DB_PASSWORD || '',
      {
        host: process.env.DB_HOST || 'localhost',
        dialect: 'postgres',
        dialectOptions: {
          ssl: process.env.DB_SSL === 'true' ? {
            require: true,
            rejectUnauthorized: false
          } : false
        },
        logging: false,
    }
  );
  const sessionStore = new pgSession({
  // Re-use the already configured pg connection pool so we don’t maintain
  // two separate pools and we inherit the same credentials/SSL settings.
  pool,
  tableName: 'user_sessions',
  createTableIfMissing: true,
  pruneSessionInterval: 60 // seconds
});
  
  app.use(session({
    key: 'session_cookie_name',
    secret: 'your-secret-key-change-this',
    store: sessionStore,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // Set to true if using HTTPS
      sameSite: 'lax',
      maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
  }));


// const RegisteredUser = sequelize.define('RegisteredUsers', {
//   acno: { type: DataTypes.STRING, allowNull: false, primaryKey: false},
//   name: DataTypes.STRING,
 
//   address: DataTypes.STRING,
//   holdings: DataTypes.STRING,
//   phone_number: DataTypes.STRING,
//   email: DataTypes.STRING,
//   chn: DataTypes.STRING,
//   rin: DataTypes.STRING,
//   hasVoted: { type: Sequelize.BOOLEAN, defaultValue: false }
// }, {
//   timestamps: false,
//   freezeTableName: true
//   

const RegisteredUser = sequelize.define('registeredusers', {
  name: DataTypes.STRING,
  acno: DataTypes.STRING,
  holdings: {
    type: DataTypes.DECIMAL(15, 2),
    defaultValue: 0 // Add this
  },
  chn: { type:Sequelize.STRING, allowNull: true },
  email: DataTypes.STRING,
  phone_number: DataTypes.STRING,
  registered_at: {
    type: DataTypes.DATE,
    defaultValue: DataTypes.NOW
  },
  sessionId: DataTypes.STRING, 
  
  
});

  

// Audit Committee Member Model
const AuditCommittee = sequelize.define('AuditCommittee', {
  id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
  name: { type: Sequelize.STRING, allowNull: false },
  bio: { type: Sequelize.TEXT },
  isActive: { 
    type: Sequelize.BOOLEAN, 
    defaultValue: false 
  },
  votesFor: {
    type: Sequelize.INTEGER,
    defaultValue: 0
  }
});

// Audit Vote Model
const AuditVote = sequelize.define('AuditVote', {
  id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
  voterId: {
    type: Sequelize.INTEGER,
    allowNull: false,
    references: {
      model: 'registeredusers',
      key: 'id'
    }
  }
});



// Sync models with database - force true will drop and recreate tables


const Resolution = sequelize.define('Resolution', {
  id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
  title: Sequelize.STRING,
  description: Sequelize.TEXT,

  order: {
    type: Sequelize.INTEGER,
    defaultValue: 0,
    allowNull: false
  },
 
  isActive: {
    type: Sequelize.BOOLEAN,
    defaultValue: false
  },

  proxyVotes: {
    type: Sequelize.INTEGER,
    defaultValue: 0,
    allowNull: false
  },
  
},
 {
  indexes: [
    {
      fields: ['order']
    }
  ]
  
});







io.on('connection', (socket) => {
  console.log('New client connected');


  // Audit Committee Socket Events
  socket.on('new-audit-vote', async ({ committeeId }) => {
    try {
      const committee = await AuditCommittee.findByPk(committeeId, {
        attributes: ['id', 'votesFor']
      });
      
      if (committee) {
        io.emit('audit-vote-updated', {
          committeeId: committee.id,
          votesFor: committee.votesFor,
          totalVotes: committee.votesFor
        });
      }
    } catch (error) {
      console.error('Error updating audit vote counts:', error);
      socket.emit('audit-vote-error', { 
        message: 'Failed to update audit vote counts',
        committeeId
      });
    }
  });

  socket.on('new-vote', async ({ resolutionId }) => {
    try {
      const voteCounts = await Vote.findAll({
        where: { ResolutionId: resolutionId },
        attributes: [
          [sequelize.fn('COUNT', sequelize.col('id')), 'total'],
          [sequelize.fn('SUM', sequelize.cast(sequelize.col('decision'), 'integer')), 'yes'],
        ],
        raw: true
        
});
  
      // Safely extract counts and ensure they are numbers
      const counts = voteCounts[0] || { total: 0, yes: 0 };
      const total = parseInt(counts.total) || 0;
      const yes = parseInt(counts.yes) || 0;
      const no = total - yes;
  
      io.emit('vote-updated', {
        resolutionId,
        yes,
        no,
        total // Make sure this is included
        
});
    } catch (error) {
      console.error('Error updating vote counts:', error);
      socket.emit('vote-error', { 
        message: 'Failed to update vote counts',
        resolutionId
        
});
    }
    
});




  // Send current state to new connections
  Resolution.findOne({ where: { isActive: true } }).then(resolution => {
    if (resolution) {
      socket.emit('resolution-activated', resolution);
    }
    
});
  socket.emit('voting-state', votingState);
  
});

const broadcastResolutionUpdate = async () => {
  const activeResolution = await Resolution.findOne({ 
    where: { isActive: true },
    include: [Vote]
    
});
  io.emit('resolution-update', activeResolution);
};

let votingState = {
  isOpen: false,
  type: null, // 'resolution' or 'audit'
  activeId: null
};

const setVotingState = (isOpen, type, activeId) => {
  votingState = { isOpen, type, activeId };
  io.emit('voting-state', votingState);
};


app.post('/api/admin/voting/open', (req, res) => {
  setVotingState(true);
  io.emit('voting-toggle', true);
  res.json({ success: true   
});
  
});

// Get current voting state
app.get('/api/admin/voting/state', (req, res) => {
  res.json(votingState);
});

// Toggle voting state and broadcast to clients
app.post('/api/admin/voting/toggle', (req, res) => {
  const { type, activeId } = req.body;
  if (!type || !activeId) {
    return res.status(400).json({ error: 'type and activeId required' });
  }
  const newState = !votingState.isOpen;
  setVotingState(newState, type, activeId);
  return res.json(votingState);
});

app.post('/api/admin/voting/close', (req, res) => {
  setVotingState(false);
  io.emit('voting-toggle', false);
  res.json({ success: true   
});
  
});





const Vote = sequelize.define('Vote', {
  id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
  decision: { type: Sequelize.BOOLEAN, allowNull: false },
  holdings: {
    type: DataTypes.INTEGER,
    defaultValue: 0 // Add this
  },
  
});




// Define associations
RegisteredUser.hasMany(Vote, { foreignKey: 'registereduserId' });
Resolution.hasMany(Vote);
Vote.belongsTo(RegisteredUser, { foreignKey: 'registereduserId' });
Vote.belongsTo(Resolution, { foreignKey: 'ResolutionId' });

AuditCommittee.hasMany(AuditVote, { onDelete: 'CASCADE' });
AuditVote.belongsTo(AuditCommittee);
RegisteredUser.hasMany(AuditVote);
AuditVote.belongsTo(RegisteredUser);


// Add these to your model associations
AuditCommittee.hasMany(AuditVote, { foreignKey: 'AuditCommitteeId' });
AuditVote.belongsTo(AuditCommittee, { foreignKey: 'AuditCommitteeId' });
AuditVote.belongsTo(RegisteredUser, { foreignKey: 'voterId' });
RegisteredUser.hasMany(AuditVote, { foreignKey: 'voterId' });
// Sync database
sequelize.sync().then(() => {
  console.log('Database & tables created!');
  
});

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static('public'));


app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', 'http://localhost:5173');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

app.use(cors({
  origin: 'http://localhost:5173', // Vite default port
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
// Routes

// Admin ends AGM and thanks shareholders
app.post('/api/admin/agm/end', (req, res) => {
  io.emit('agm-finished', {
    message: 'Thank you for participating in the AGM. Voting has now closed.'
  });
  res.json({ success: true });
});

// Authentication routes
app.post('/api/login', async (req, res) => {
  const { identifier } = req.body;
  
  try {
    // Determine if identifier is an email or phone number
    let user;
    const emailRegex = /^[\w.-]+@[\w.-]+\.[A-Za-z]{2,}$/;

    if (emailRegex.test(identifier)) {
      // Login by email
      user = await RegisteredUser.findOne({ where: { email: identifier } });
    } else {
      // Treat as phone number, build possible variants
      const digitsOnly = String(identifier).replace(/\D/g, '');
      let variants = [];

      if (digitsOnly.startsWith('0')) {
        // 0803…  -> [0803…, 234803…]
        variants = [
          digitsOnly,
          '234' + digitsOnly.slice(1),
          '+234' + digitsOnly.slice(1)
        ];
      } else if (digitsOnly.startsWith('234')) {
        // 234803…  -> [234803…, 0803…]
        variants = [
          digitsOnly,
          '+'+digitsOnly,
          '0' + digitsOnly.slice(3)
        ];
      } else {
        // e.g. 8031234567 -> try both local & intl
        variants = [
          digitsOnly,
          '+'+digitsOnly,
          '0' + digitsOnly,
          '234' + digitsOnly,
          '+234' + digitsOnly
        ];
      }

      user = await RegisteredUser.findOne({
        where: {
          phone_number: { [Sequelize.Op.in]: variants }
        }
      });
    }

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if user already has an active session
    // if (user.sessionId) {
    //   // User already has an active session – refuse new login
    //   return res.status(409).json({
    //     error: 'User already logged in elsewhere'
    //   });
    // }

    // Create new session
    req.session.regenerate(async (err) => {
      if (err) {
        console.error('Session regeneration error:', err);
        return res.status(500).json({ error: 'Login failed' });
      }

      req.session.userId = user.id;
      req.session.userName = user.name;

      // Update user with current session ID
      await user.update({ sessionId: req.sessionID });

      req.session.save((err) => {
        if (err) {
          console.error('Session save error:', err);
          return res.status(500).json({ error: 'Login failed' });
        }

        res.json({ 
          success: true,
          message: `Welcome ${user.name}`,
          user: { id: user.id, name: user.name }
        });
      });
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
}); // Close /api/login route properly

 // Get all resolutions with vote counts
 app.get('/api/resolutions', async (req, res) => {
  try {
    // First get all resolutions without vote counts
    const resolutions = await Resolution.findAll({
      attributes: ['id', 'title', 'description', 'order', 'isActive'],
      order: [['order', 'ASC']]
    });

    // Then get vote counts in a separate query
    const voteCounts = await Vote.findAll({
      attributes: [
        'ResolutionId',
        [sequelize.fn('COUNT', sequelize.col('id')), 'totalVotes'],
        [sequelize.fn('SUM', sequelize.cast(sequelize.col('decision'), 'integer')), 'yesVotes']
      ],
      group: ['ResolutionId']
    });

    // Combine the data
    const formattedResolutions = resolutions.map(resolution => {
      const counts = voteCounts.find(v => v.get('ResolutionId') === resolution.id) || {
        dataValues: { totalVotes: 0, yesVotes: 0 }
      };
      
      return {
        id: resolution.id,
        title: resolution.title,
        description: resolution.description,
        order: resolution.order,
        isActive: resolution.isActive,
        yesVotes: counts.dataValues.yesVotes || 0,
        noVotes: (counts.dataValues.totalVotes || 0) - (counts.dataValues.yesVotes || 0)
      };
    });

    res.json(formattedResolutions);
  } catch (error) {
    console.error('Error fetching resolutions:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch resolutions',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});
// Get current voting state
app.get('/api/admin/voting/state', (req, res) => {
  res.json({ isOpen: votingState   
});
  
});

// Add this to your server.js file
app.put('/api/admin/audit-committee/:id/activate', async (req, res) => {
  try {
    // Start a transaction
    const transaction = await sequelize.transaction();
    
    // Deactivate all other committee members
    await AuditCommittee.update(
      { isActive: false },
      { where: { id: { [Op.ne]: req.params.id } }, transaction }
    );
    
    // Activate the selected member
    const member = await AuditCommittee.findByPk(req.params.id, { transaction });
    if (!member) {
      await transaction.rollback();
      return res.status(404).json({ error: 'Audit committee member not found' });
    }
    
    await member.update({ isActive: true }, { transaction });
    
    // Commit the transaction
    await transaction.commit();
    
    // Set voting state (if needed)
    setVotingState(false, 'audit', member.id);
    
    // Broadcast updates
    io.emit('audit-member-updated', member);
    
    res.json(member);
  } catch (error) {
    await transaction.rollback();
    console.error('Error activating audit member:', error);
    res.status(500).json({ error: 'Failed to activate audit committee member' });
  }
});

app.put('/api/admin/resolutions/:id/activate', async (req, res) => {
  try {
    // Deactivate all other resolutions and audit members
    await Resolution.update({ isActive: false }, { where: {} });
    await AuditCommittee.update({ isActive: false }, { where: {} });
    
    // Activate the selected resolution
    const resolution = await Resolution.findByPk(req.params.id);
    await resolution.update({ isActive: true });
    
    // Set voting state
    setVotingState(false, 'resolution', resolution.id);
    
    // Broadcast updates
    io.emit('resolution-update', resolution);
    res.json(resolution);
  } catch (error) {
    res.status(500).json({ error: 'Failed to activate resolution' });
  }
});

// Voting route
// app.post('/vote', async (req, res) => {
//   if (!req.session.userId) return res.status(401).send('Unauthorized');
  
//   try {
//     const user = await RegisteredUser.findByPk(req.session.userId);
//     if (user.hasVoted) return res.status(400).send('Already voted');

//     const { resolutionId, decision } = req.body;
    
//     await Vote.create({
//       decision,
//       registereduserId: user.id,
//       ResolutionId: resolutionId
//       


//     await user.update({ hasVoted: true   

//     res.send('Vote recorded successfully');
//   } catch (error) {
//     res.status(500).send('Error recording vote');
//   }
   


// Add to server.js
app.put('/api/admin/resolutions/:id/proxy', async (req, res) => {
  try {
    const { proxyVotes } = req.body;
    
    if (typeof proxyVotes !== 'number' || proxyVotes < 0) {
      return res.status(400).json({ error: 'Invalid proxy vote count'   
});
    }

    const resolution = await Resolution.findByPk(req.params.id);
    if (!resolution) {
      return res.status(404).json({ error: 'Resolution not found'   
});
    }

    await resolution.update({ proxyVotes   
});
    
    // Broadcast updated resolution
    if (resolution.isActive) {
      const activeResolution = await Resolution.findOne({
        where: { isActive: true },
        include: [Vote]
        
});
      io.emit('resolution-update', activeResolution);
    }

    res.json({ success: true, proxyVotes   
});
  } catch (error) {
    console.error('Proxy vote error:', error);
    res.status(500).json({ error: 'Failed to update proxy votes'   
});
  }
  
});

app.get('/api/voting/resolutions', async (req, res) => {
  try {
    const resolutions = await Resolution.findAll({
      attributes: ['id', 'title', 'description', 'order'],
      order: [['order', 'ASC']]
      
});
    
    res.json(resolutions);
  } catch (error) {
    console.error('Voting API error:', error);
    res.status(500).json({ error: 'Failed to fetch voting resolutions'   
});
  }
  
});

// server.js - Updated resolution endpoint
app.post('/api/admin/resolutions', async (req, res) => {
  // Add basic validation
  if (!req.body.title || !req.body.description) {
    return res.status(400).json({ 
      error: 'Title and description are required' 
      
});
  }

  try {
    const resolution = await Resolution.create({
      title: req.body.title,
      description: req.body.description
      
});
    
    // Return the created resolution with 201 status
    res.status(201).json(resolution);
    
  } catch (error) {
    console.error('Creation error:', {
      error: error.name,
      message: error.message,
      validationErrors: error.errors
      
});
    
    res.status(500).json({ 
      error: 'Database operation failed',
      details: error.message 
      
});
  }
  
});
// PUT - Update resolution
app.put('/api/resolutions/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const resolution = await Resolution.findByPk(id);
    if (!resolution) return res.status(404).json({ error: 'Resolution not found'   
});

    await resolution.update(req.body);
    res.json(resolution);
  } catch (error) {
    res.status(500).json({ error: 'Error updating resolution'   
});
  }
  
});

// DELETE - Remove resolution
app.delete('/api/resolutions/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const resolution = await Resolution.findByPk(id);
    if (!resolution) return res.status(404).json({ error: 'Resolution not found'   
});

    await resolution.destroy();
    res.json({ message: 'Resolution deleted successfully'   
});
  } catch (error) {
    res.status(500).json({ error: 'Error deleting resolution'   
});
  }
  
});
// Results route
// Updated /api/results endpoint
app.get('/api/results', async (req, res) => {
  try {
    // First get all resolutions without vote counts
    const resolutions = await Resolution.findAll({
      attributes: ['id', 'title', 'description', 'isActive', 'createdAt'],
      order: [['createdAt', 'DESC']]
      
});

    // Then get vote counts in a separate query
    const voteCounts = await Vote.findAll({
      attributes: [
        'ResolutionId',
        [sequelize.fn('COUNT', sequelize.col('id')), 'totalVotes'],
        [sequelize.fn('SUM', sequelize.cast(sequelize.col('decision'), 'integer')), 'yesVotes']
      ],
      group: ['ResolutionId']
      
});

    // Combine the data
    const formattedResults = resolutions.map(res => {
      const counts = voteCounts.find(v => v.dataValues.ResolutionId === res.id)?.dataValues || {
        totalVotes: 0,
        yesVotes: 0
      };
      
      const total = counts.totalVotes || 0;
      const yes = counts.yesVotes || 0;
      const no = total - yes;
      
      return {
        id: res.id,
        title: res.title,
        description: res.description,
        isActive: res.isActive,
        totalVotes: total,
        yesVotes: yes,
        noVotes: no,
        percentageYes: total > 0 ? Math.round((yes / total) * 100) : 0,
        percentageNo: total > 0 ? Math.round((no / total) * 100) : 0,
        status: res.isActive ? 'Active' : yes > no ? 'Passed' : 'Rejected'
      };
      
});

    res.json({
      success: true,
      data: formattedResults,
      timestamp: new Date().toISOString()
      
});
  } catch (error) {
    console.error('Results error:', error);
    res.status(500).json({
      success: false,
      error: 'Failed to fetch results',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
      
});
  }
  
});

// Get results for specific resolution
app.get('/api/results/:id', async (req, res) => {
  try {
    const resolution = await Resolution.findByPk(req.params.id, {
      attributes: ['id', 'title', 'description', 'createdAt']
      
});

    if (!resolution) {
      return res.status(404).json({ error: 'Resolution not found'   
});
    }

    const votes = await Vote.findAll({
      where: { ResolutionId: req.params.id },
      include: [{
        model: RegisteredUser,
        attributes: ['id', 'name', 'holdings'],
        required: false
      }],
      order: [['createdAt', 'DESC']]
      
});

    // Calculate votes and holdings
    const totalVotes = votes.length;
    const yesVotes = votes.filter(v => v.decision).length;
    const noVotes = totalVotes - yesVotes;

    // Calculate holdings - use vote.holdings first, fall back to user.holdings
    const totalHoldings = votes.reduce((sum, vote) => {
      const holdings = vote.holdings || (vote.RegisteredUser ? vote.RegisteredUser.holdings : 0);
      return sum + (holdings || 0);
    }, 0);

    const yesHoldings = votes.reduce((sum, vote) => {
      if (vote.decision) {
        const holdings = vote.holdings || (vote.RegisteredUser ? vote.RegisteredUser.holdings : 0);
        return sum + (holdings || 0);
      }
      return sum;
    }, 0);

    const noHoldings = totalHoldings - yesHoldings;

    // Format voter details
    const voterDetails = votes.map(vote => ({
      id: vote.id,
      decision: vote.decision ? 'Yes' : 'No',
      votedAt: vote.createdAt,
      holdings: vote.holdings || (vote.RegisteredUser ? vote.RegisteredUser.holdings : 0),
      voter: vote.RegisteredUser ? {
        id: vote.RegisteredUser.id,
        name: vote.RegisteredUser.name
      } : {
        id: null,
        name: 'Unknown Voter'
      }
    }));

    res.json({
      success: true,
      data: {
        resolution,
        summary: {
          totalVotes,
          yesVotes,
          noVotes,
          percentageYes: totalVotes > 0 ? Math.round((yesVotes / totalVotes) * 100) : 0,
          percentageNo: totalVotes > 0 ? Math.round((noVotes / totalVotes) * 100) : 0,
          totalHoldings,
          yesHoldings,
          noHoldings,
          percentageYesHoldings: totalHoldings > 0 ? Math.round((yesHoldings / totalHoldings) * 100) : 0,
          percentageNoHoldings: totalHoldings > 0 ? Math.round((noHoldings / totalHoldings) * 100) : 0
        },
        votes: voterDetails
      }
      
});
  } catch (error) {
    console.error('Results error:', error);
    res.status(500).json({ error: 'Failed to fetch results'   
});
  }
  
});

// Frontend routes
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/login.html');
  
});

app.get('/dashboard', (req, res) => {
  if (!req.session.userId) return res.redirect('/');
  res.sendFile(__dirname + '/public/dashboard.html');
  
});

app.get('/results-page', (req, res) => {
  res.sendFile(__dirname + '/public/results.html');
  
});

// Get all resolutions
app.get('/resolutions', async (req, res) => {
  try {
    const resolutions = await Resolution.findAll();
    res.json(resolutions);
  } catch (error) {
    res.status(500).send('Error fetching resolutions');
  }
  
});


// Add these endpoints
// app.get('/api/active-resolution', async (req, res) => {
//   try {
//     const resolution = await Resolution.findOne({ 
//       where: { isActive: true },
//       include: [{
//         model: Vote,
//         attributes: [
//           [Sequelize.fn('COUNT', Sequelize.fn('IF', Sequelize.col('decision'), 1, null)), 'yesVotes'],
//           [Sequelize.fn('COUNT', Sequelize.fn('IF', Sequelize.literal('NOT decision'), 1, null)), 'noVotes']
//         ]
//       }]
//       

    
//     if (!resolution) return res.json({ active: false   
// //     console.log(resolution);
//     res.json({
//       active: true,
//       title: resolution.title,
//       description: resolution.description,
//       yes: resolution.Votes[0].dataValues.yesVotes,
//       no: resolution.Votes[0].dataValues.noVotes
//       

//   } catch (error) {
//     res.status(500).json({ error: 'Failed to get active resolution'   
// //     console.error(error);
//   }
//   


// Admin-only endpoint
// Add these endpoints

// Activate a resolution
// In server.js, update the resolution activation

// app.post('/api/admin/voting/open', async (req, res) => {
//   votingState = true;
//   io.emit('voting-state', true);
//   res.json({ success: true   
// //   console.log('Voting opened');
// });

// app.post('/api/admin/voting/close', async (req, res) => {
//   votingState = false;
//   io.emit('voting-state', false);
//   res.json({ success: true   
// //   console.log('Voting closed');
//   

// Close current resolution

// Close Resolution
app.post('/api/admin/resolutions/close', async (req, res) => {
  try {
    await Resolution.update({ isActive: false }, { where: { isActive: true }   
});
    votingState = false; // Also close voting when resolution closes
    
    // Broadcast updates
    io.emit('resolution-closed');
    io.emit('voting-state', false);
    
    res.json({ success: true   
});
  } catch (error) {
    res.status(500).json({ error: 'Failed to close resolution'   
});
  }
  
});


// Change from /api/audit-committee/active to /api/admin/audit-committee/active
app.get('/api/admin/audit-committee/active', async (req, res) => {
  try {
    const member = await AuditCommittee.findOne({ 
      where: { isActive: true },
      include: [{
        model: AuditVote,
        attributes: ['id'],
        include: [{
          model: RegisteredUser,
          attributes: ['id', 'name', 'holdings']
        }]
      }]
    });
    
    if (!member) {
      return res.status(404).json({ 
        success: false,
        error: 'No active audit committee member',
        data: null
      });
    }
    
    const votesFor = await AuditVote.count({
      where: { AuditCommitteeId: member.id }
    });
    
    res.json({
      success: true,
      data: {
        ...member.toJSON(),
        votesFor
      }
    });
  } catch (error) {
    console.error('Error:', error);
    res.status(500).json({
      success: false,
      error: 'Server error',
      data: null
    });
  }
});

// Add this endpoint for /api/active-resolution
app.get('/api/active-resolution', async (req, res) => {
  try {
    const resolution = await Resolution.findOne({ where: { isActive: true } });
    if (!resolution) return res.status(404).json({ success: false, error: 'No active resolution' });
    res.json({ success: true, data: resolution });
  } catch (error) {
    res.status(500).json({ success: false, error: 'Failed to fetch active resolution' });
  }
});

//Toggle Voting State
app.post('/api/admin/voting/toggle', async (req, res) => {
  try {
    const { type, activeId } = req.body;
    
    if (votingState.isOpen) {
      // Close voting
      setVotingState(false, null, null);
    } else {
      // Open voting - validate there's an active item
      if (type === 'resolution') {
        const resolution = await Resolution.findByPk(activeId);
        if (!resolution) {
          return res.status(400).json({ error: 'Resolution not found' });
        }
      } else if (type === 'audit') {
        const member = await AuditCommittee.findByPk(activeId);
        if (!member) {
          return res.status(400).json({ error: 'Committee member not found' });
        }
      }
      
      setVotingState(true, type, activeId);
    }
    
    res.json(votingState);
  } catch (error) {
    res.status(500).json({ error: 'Failed to toggle voting' });
  }
});

// Get active resolution

// Update results endpoint

// Update check-vote endpoint
app.get('/api/check-vote', requireAuth, async (req, res) => {
  try {
    const activeResolution = await Resolution.findOne({ 
      where: { isActive: true } 
      
});
    
    if (!activeResolution) {
      return res.json({ hasVoted: false   
});
    }

    const vote = await Vote.findOne({
      where: {
        registereduserId: req.session.userId,
        ResolutionId: activeResolution.id
      }
      
});

    res.json({ 
      hasVoted: !!vote,
      userId: req.session.userId // For debugging
      
});
  } catch (error) {
    console.error('Check vote error:', error);
    res.status(500).json({ error: 'Failed to check vote status'   
});
  }
  
});

// Update vote endpoint

app.post('/api/vote', requireAuth, async (req, res) => {
  try {
    const { resolutionId, decision } = req.body;
    const userId = req.session.userId;

    // Validate input
    if (typeof decision !== 'boolean' || !resolutionId) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid vote data' 
      });
    }

    // Get user with EXPLICIT holdings inclusion
    const user = await RegisteredUser.findByPk(userId, {
      attributes: ['id', 'name', 'holdings'], // Explicitly include holdings
      raw: true // Get plain object instead of model instance
    });
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Validate holdings exists and is a number
    if (user.holdings === undefined || user.holdings === null) {
      console.warn(`User ${userId} has no holdings value`);
      user.holdings = 0; // Set default if missing
    }

    // Check if already voted
    const existingVote = await Vote.findOne({
      where: {
        registereduserId: userId,
        ResolutionId: resolutionId
      }
    });

    if (existingVote) {
      return res.status(400).json({ error: 'Already voted' });
    }

    // Record vote with holdings
    const vote = await Vote.create({
      decision,
      registereduserId: userId,
      ResolutionId: resolutionId,
      holdings: Number(user.holdings) || 0 // Ensure it's a number
    });

    // Calculate vote counts with holdings
    const voteCounts = await Vote.findAll({
      where: { ResolutionId: resolutionId },
      attributes: [
        [sequelize.fn('COUNT', sequelize.col('id')), 'total'],
        [sequelize.fn('SUM', sequelize.cast(sequelize.col('decision'), 'integer')), 'yes'],
        [sequelize.literal('SUM(CASE WHEN NOT decision THEN 1 ELSE 0 END)'), 'no'],
        [sequelize.fn('SUM', sequelize.col('holdings')), 'totalHoldings'],
        [sequelize.fn('SUM', sequelize.literal('CASE WHEN decision THEN holdings ELSE 0 END')), 'yesHoldings'],
        [sequelize.fn('SUM', sequelize.literal('CASE WHEN NOT decision THEN holdings ELSE 0 END')), 'noHoldings']
      ],
      raw: true
    });

    const counts = voteCounts[0] || {
      total: 0, yes: 0, no: 0,
      totalHoldings: 0, yesHoldings: 0, noHoldings: 0
    };

    // Broadcast update with holdings data
    io.emit('vote-updated', {
      resolutionId,
      yes: counts.yes || 0,
      no: counts.no || 0,
      total: counts.total || 0,
      yesHoldings: counts.yesHoldings || 0,
      noHoldings: counts.noHoldings || 0,
      totalHoldings: counts.totalHoldings || 0
    });

    res.json({ 
      success: true,
      message: 'Vote recorded successfully',
      vote: {
        id: vote.id,
        decision: vote.decision,
        holdings: vote.holdings
      }
    });
  } catch (error) {
    console.error('Vote error:', error);
    res.status(500).json({ error: 'Failed to record vote' });
  }
});


// Submit a vote
// Handle votes

app.post('/api/logout', async (req, res) => {
  if (req.session.userId) {
    try {
      await RegisteredUser.update(
        { sessionId: null },
        { where: { id: req.session.userId } }
      );
    } catch (error) {
      console.error('Error clearing sessionId:', error);
    }
  }
  
  req.session.destroy(() => {
    res.json({ success: true   
});
    
});
  
});

// Add middleware to check for concurrent sessions
const checkConcurrentSession = async (req, res, next) => {
  if (!req.session.userId) return next();
  
  try {
    const user = await RegisteredUser.findByPk(req.session.userId);
    if (!user || user.sessionId !== req.sessionID) {
      req.session.destroy();
      return res.status(401).json({ 
        error: 'Logged in elsewhere' 
        
});
    }
    next();
  } catch (error) {
    next(error);
  }
};

app.use('/api', checkConcurrentSession);

// Audit Committee API Endpoints

// Get all audit committee members
// In server.js, add these endpoints if not already present:

// Get all audit committee members
app.get('/api/audit-committee', async (req, res) => {
  try {
    const members = await AuditCommittee.findAll({
      order: [['createdAt', 'ASC']]
    });
    res.json(members);
  } catch (error) {
    console.error('Error fetching audit committee:', error);
    res.status(500).json({ error: 'Failed to fetch audit committee' });
  }
});

// Create new audit committee member
app.post('/api/audit-committee', async (req, res) => {
  try {
    const { name, bio } = req.body;
    const member = await AuditCommittee.create({ name, bio });
    res.status(201).json(member);
  } catch (error) {
    console.error('Error creating audit committee member:', error);
    res.status(500).json({ error: 'Failed to create audit committee member' });
  }
});

// Update audit committee member
// Update audit committee member
app.put('/api/audit-committee/:id',async (req, res) => {
  const transaction = await sequelize.transaction();
  
  try {
    const { name, bio, isActive } = req.body;
    const member = await AuditCommittee.findByPk(req.params.id, { transaction });
    
    if (!member) {
      await transaction.rollback();
      return res.status(404).json({ error: 'Audit committee member not found' });
    }
    
    // If activating this member, deactivate all others
    if (isActive && !member.isActive) {
      await AuditCommittee.update(
        { isActive: false },
        { where: { id: { [Op.ne]: member.id } }, transaction }
      );
    }
    
    // Update the member
    const updatedMember = await member.update(
      { name, bio, isActive },
      { transaction }
    );
    
    await transaction.commit();
    
    // Broadcast the update
    io.emit('audit-member-updated', updatedMember);
    res.json(updatedMember);
  } catch (error) {
    await transaction.rollback();
    console.error('Error updating audit committee member:', error);
    res.status(500).json({ error: 'Failed to update audit committee member' });
  }
});

// Delete audit committee member
app.delete('/api/audit-committee/:id',  async (req, res) => {
  const transaction = await sequelize.transaction();
  
  try {
    const member = await AuditCommittee.findByPk(req.params.id, { transaction });
    
    if (!member) {
      await transaction.rollback();
      return res.status(404).json({ error: 'Audit committee member not found' });
    }
    
    // Delete associated votes first if needed
    await AuditVote.destroy({
      where: { AuditCommitteeId: member.id },
      transaction
    });
    
    await member.destroy({ transaction });
    await transaction.commit();
    
    // Broadcast the deletion
    io.emit('audit-member-deleted', { id: member.id });
    res.status(204).send();
  } catch (error) {
    await transaction.rollback();
    console.error('Error deleting audit committee member:', error);
    res.status(500).json({ error: 'Failed to delete audit committee member' });
  }
});

// Get active audit committee member
app.get('/api/admin/audit-committee/active', async (req, res) => {
  try {
    const member = await AuditCommittee.findOne({ 
      where: { isActive: true },
      include: [{
        model: AuditVote,
        attributes: ['id'],
        include: [{
          model: RegisteredUser,
          attributes: ['id', 'name', 'holdings']
        }]
      }]
    });
    
    if (!member) {
      return res.status(404).json({ error: 'No active audit committee member' });
    }
    
    // Calculate total votes
    const votesFor = await AuditVote.count({
      where: { AuditCommitteeId: member.id }
    });
    
    const response = member.toJSON();
    response.votesFor = votesFor;
    
    res.json(response);
  } catch (error) {
    console.error('Error fetching active audit member:', error);
    res.status(500).json({ error: 'Failed to fetch active audit member' });
  }
});

// Get active audit committee member
app.get('/api/audit-committee/active', async (req, res) => {
  try {
    const member = await AuditCommittee.findOne({ where: { isActive: true } });
    if (!member) return res.json(null);
    return res.json(member);
  } catch (err) {
    console.error('Error fetching active audit committee member', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Get active resolution
app.get('/api/active-resolution', async (req, res) => {
  try {
    const resolution = await Resolution.findOne({ where: { isActive: true } });
    if (!resolution) return res.json(null);
    return res.json(resolution);
  } catch (err) {
    console.error('Error fetching active resolution', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Submit audit vote
app.post('/api/audit-vote', requireAuth, async (req, res) => {
  const transaction = await sequelize.transaction();
  
  try {
    const { committeeId } = req.body;
    if (!committeeId) {
      return res.status(400).json({ error: 'committeeId is required' });
    }
    const userId = req.session.userId;

    // Check if user has already voted
    const existingVote = await AuditVote.findOne({
      where: { 
        voterId: userId,
        '$AuditCommittee.isActive$': true
      },
      include: [{
        model: AuditCommittee,
        attributes: []
      }],
      transaction
    });

    if (existingVote) {
      await transaction.rollback();
      return res.status(400).json({ error: 'You have already voted in this election' });
    }

    // Create vote
    await AuditVote.create({
      voterId: userId,
      AuditCommitteeId: committeeId
    }, { transaction });

    // Update vote count
    await AuditCommittee.increment({ votesFor: 1 }, {
      where: { id: committeeId },
      transaction
    });

    await transaction.commit();
    
    // Broadcast update
    const committee = await AuditCommittee.findByPk(committeeId);
    io.emit('audit-vote-updated', {
      committeeId: committee.id,
      votesFor: committee.votesFor,
      totalVotes: committee.votesFor
    });

    res.json({ success: true });
  } catch (error) {
    await transaction.rollback();
    console.error('Error submitting audit vote:', error);
    res.status(500).json({ error: 'Failed to submit vote' });
  }
});

// Get active audit committee member




// Public endpoint to get currently active resolution
app.get('/api/active-resolution', async (req, res) => {
  try {
    const active = await Resolution.findOne({ where: { isActive: true } });
    if (!active) {
      return res.status(404).json({ error: 'No active resolution' });
    }

    // Aggregate vote counts (yes / no)
    const counts = await Vote.findAll({
      where: { ResolutionId: active.id },
      attributes: [
        [sequelize.fn('COUNT', sequelize.col('id')), 'total'],
        [sequelize.fn('SUM', sequelize.cast(sequelize.col('decision'), 'integer')), 'yes']
      ],
      raw: true
    });

    const total = parseInt(counts[0]?.total || 0);
    const yes = parseInt(counts[0]?.yes || 0);
    const no = total - yes;

    res.json({ success: true, data: { ...active.toJSON(), voteCounts: { yes, no, total } } });
  } catch (err) {
    console.error('Error fetching active resolution:', err);
    res.status(500).json({ error: 'Failed to fetch active resolution' });
  }
});

// Public endpoint to get currently active audit committee member (alias for admin route)
app.get('/api/audit-committee/active', async (req, res) => {
  try {
    const member = await AuditCommittee.findOne({ where: { isActive: true } });
    if (!member) return res.status(404).json({ error: 'No active audit committee member' });

    const votesFor = await AuditVote.count({ where: { AuditCommitteeId: member.id } });
    res.json({ success: true, data: { ...member.toJSON(), votesFor } });
  } catch (err) {
    console.error('Error fetching active audit member:', err);
    res.status(500).json({ error: 'Failed to fetch active audit member' });
  }
});

// Check if logged-in user has voted on the active resolution
app.get('/api/check-vote', requireAuth, async (req, res) => {
  try {
    const active = await Resolution.findOne({ where: { isActive: true } });
    if (!active) return res.json({ hasVoted: false });

    const vote = await Vote.findOne({
      where: { registereduserId: req.session.userId, ResolutionId: active.id }
    });
    res.json({ hasVoted: !!vote });
  } catch (err) {
    console.error('Error checking vote status:', err);
    res.status(500).json({ error: 'Failed to check vote status' });
  }
});

// Check if logged-in user has voted on the active audit committee election
app.get('/api/check-audit-vote', requireAuth, async (req, res) => {
  try {
    const active = await AuditCommittee.findOne({ where: { isActive: true } });
    if (!active) return res.json({ hasVoted: false });

    const vote = await AuditVote.findOne({
      where: { voterId: req.session.userId, AuditCommitteeId: active.id }
    });
    res.json({ hasVoted: !!vote });
  } catch (err) {
    console.error('Error checking audit vote status:', err);
    res.status(500).json({ error: 'Failed to check audit vote status' });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  
});