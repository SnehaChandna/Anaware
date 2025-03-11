import { Hono } from 'hono';
import { PrismaClient } from '@prisma/client/edge';
import { withAccelerate } from '@prisma/extension-accelerate';
import { sign, verify } from 'hono/jwt';
import { cors } from 'hono/cors';

interface TokenData {
  access_token: string;
}

interface UserInfo {
  email: string;
}

const app = new Hono<{
  Bindings: {
    DATABASE_URL: string;
    JWT_SECRET: string;
    GOOGLE_CLIENT_ID: string;
    GOOGLE_CLIENT_SECRET: string;
    GOOGLE_REDIRECT_URI: string;
    VIRUSTOTAL_API_KEY: string;
  };
}>();
const FLASK_ENDPOINT="https://8ff1-2409-40d6-100b-6bca-c0cf-c8e2-d352-8e25.ngrok-free.app"


app.use("/*", cors({
  origin: ['https://anaware.vercel.app'],
  credentials: true,
}));

app.get('/google/login', async (c) => {
  const clientId = c.env.GOOGLE_CLIENT_ID;
  const redirectUri = c.env.GOOGLE_REDIRECT_URI;

  console.log("GOOGLE_REDIRECT_URI:", redirectUri);

  const authUrl = `https://accounts.google.com/o/oauth2/auth?response_type=code&client_id=${clientId}&redirect_uri=${redirectUri}&scope=openid%20profile%20email&access_type=offline&prompt=select_account`;

  return c.redirect(authUrl);
});


app.get('/auth/google/callback', async (c) => {
  const { code } = c.req.query();

  if (!code) {
    return c.json({ error: 'Authorization code missing' }, 400);
  }

  try {
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: c.env.GOOGLE_CLIENT_ID,
        client_secret: c.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: c.env.GOOGLE_REDIRECT_URI,
        grant_type: 'authorization_code',
      }),
    });

    if (!tokenResponse.ok) {
      return c.json({ error: 'Failed to exchange code for token' }, 500);
    }

    const tokenData: TokenData = await tokenResponse.json();

    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    if (!userInfoResponse.ok) {
      return c.json({ error: 'Failed to fetch user info' }, 500);
    }

    const userInfo: UserInfo = await userInfoResponse.json();

    const prisma = new PrismaClient({
      datasourceUrl: c.env.DATABASE_URL,
    }).$extends(withAccelerate());

    try {
      let user = await prisma.user.findUnique({
        where: { email: userInfo.email }, 
      });

      if (!user) {
        user = await prisma.user.create({
          data: {
            email: userInfo.email,
            password: '', 
          },
        });
      }

    const token = await sign(
      { id: user.id, email: user.email }, 
      c.env.JWT_SECRET
    );
    
    console.log("token:",token);

      return c.redirect(`https://anaware.vercel.app/?jwt=${token}`);
    } finally {
      await prisma.$disconnect(); 
    }
  } catch (error: any) {
    console.error("Google Auth Error:", error.message || error);
    return c.json({ error: `Google authentication failed: ${error.message || "Unknown error"}` }, 500);
  }
});


// Modify the /api/search endpoint in your backend (hono server)
app.get('/api/search', async (c) => {
  const query = c.req.query('query');
  if (!query) return c.json({ error: 'Query parameter is required' }, 400);

  try {
    const response = await fetch(`https://www.virustotal.com/api/v3/search?query=${query}`, {
      method: 'GET',
      headers: { 'x-apikey': c.env.VIRUSTOTAL_API_KEY },
    });

    const data = await response.json();
    
    // Determine if the URL/search result is malicious based on VirusTotal response
    let isMalicious = 0; // Default to not malicious
    
    // Check if data contains malicious verdict
    if (data.data && data.data.length > 0) {
      // For URLs, check the last_analysis_stats
      if (data.data[0].attributes && data.data[0].attributes.last_analysis_stats) {
        const stats = data.data[0].attributes.last_analysis_stats;
        // If any security vendor flagged it as malicious
        if (stats.malicious > 0 || stats.suspicious > 0) {
          isMalicious = 1;
        }
      }
    }
    
    // Get auth token from request header
    const authHeader = c.req.header('Authorization');
    const token = authHeader?.replace('Bearer ', '');
    
    // If the user is authenticated, save search to history
    if (token) {
      try {
        const user = await getUserFromToken(token, c.env.JWT_SECRET);
        if (user && user.id) {
          const prisma = new PrismaClient({
            datasourceUrl: c.env.DATABASE_URL,
          }).$extends(withAccelerate());
          
          try {
            // Determine if the query is a URL or a search
            const isUrl = query.startsWith('http') || query.startsWith('www.') || /\.[a-z]{2,}$/i.test(query);
            const queryType = isUrl ? 'URL' : 'SEARCH';
            
            // Create a new history record for the search with the malicious flag
            await prisma.history.create({
              data: {
                fileName: `${queryType}: ${query}`,
                mal: isMalicious, // Use the determined malicious status
                Date: new Date().toISOString(),
                userId: user.id
              }
            });
          } finally {
            await prisma.$disconnect();
          }
        }
      } catch (error) {
        console.error('Error saving search history:', error);
        // Continue even if history saving fails
      }
    }
    
    return c.json(data);
  } catch (error) {
    console.error("VirusTotal Search Error:", error);
    return c.json({ error: 'Failed to search VirusTotal' }, 500);
  }
});

// Helper function to verify JWT token
async function getUserFromToken(token: string, secret: string) {
  try {
    const payload = await verify(token, secret);
    return payload;
  } catch (error) {
    return null;
  }
}

// Add to backend (hono server)
app.post('/api/scan-file', async (c) => {
  const formData = await c.req.formData();
  const file = formData.get('file') as File | null;
  if (!file) {
    return c.json({ error: 'No file uploaded' }, 400);
  }
  // Determine file type
  const fileExtension = file.name.split('.').pop()?.toLowerCase() || '';
  const ALLOWED_EXTENSIONS_FILES = new Set(['exe', 'dll', 'bin']);
  const ALLOWED_EXTENSIONS_IMAGE = new Set(['png', 'jpg', 'jpeg']);
  const ALLOWED_EXTENSIONS_PDF = new Set(['pdf']);
  
  let flaskEndpoint: string;
  if (ALLOWED_EXTENSIONS_FILES.has(fileExtension)) {
    flaskEndpoint = 'quick_scan';
  } else if (ALLOWED_EXTENSIONS_IMAGE.has(fileExtension)) {
    flaskEndpoint = 'Image';
  } else if (ALLOWED_EXTENSIONS_PDF.has(fileExtension)) {
    flaskEndpoint = 'pdf_scan';
  } else {
    return c.json({ error: 'Unsupported file type' }, 400);
  }
  try {
    // Create FormData for Flask
    const flaskFormData = new FormData();
    const fileContent = await file.arrayBuffer();
    const blob = new Blob([fileContent], { type: file.type });
    flaskFormData.append('file', blob, file.name);
    // Forward to Flask server
    const flaskResponse = await fetch(
      `${c.env.FLASK_ENDPOINT}/${flaskEndpoint}`,
      {
        method: 'POST',
        body: flaskFormData
      }
    );
    if (!flaskResponse.ok) {
      const errorText = await flaskResponse.text();
      throw new Error(`Flask server error: ${flaskResponse.status} - ${errorText}`);
    }
   
    // Get result
    const result = await flaskResponse.json();
   
    // Get auth token from request header
    const authHeader = c.req.header('Authorization');
    const token = authHeader?.replace('Bearer ', '');
   
    // If the user is authenticated, save scan to history
    if (token) {
      try {
        const user = await getUserFromToken(token, c.env.JWT_SECRET);
        if (user && user.id) {
          const prisma = new PrismaClient({
            datasourceUrl: c.env.DATABASE_URL,
          }).$extends(withAccelerate());
         
          // Determine if file is malicious based on prediction
          const isMalicious = result.prediction === 'malicious' ? 1 : 0;
         
          try {
            // Create a new history record
            await prisma.history.create({
              data: {
                fileName: `FILE: ${file.name}`, // Add FILE prefix for better identification in history
                mal: isMalicious,
                Date: new Date().toISOString(),
                userId: user.id
              }
            });
          } finally {
            await prisma.$disconnect();
          }
        }
      } catch (error) {
        console.error('Error saving history:', error);
        // Continue even if history saving fails
      }
    }
    return c.json(result);
  } catch (error) {
    console.error('Error processing file:', error);
    return c.json(
      {
        error: 'Failed to process file',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      500
    );
  }
});

// New endpoint to get user's history
app.get('/api/user/history', async (c) => {
  const authHeader = c.req.header('Authorization');
  if (!authHeader) {
    return c.json({ error: 'Authentication required' }, 401);
  }
  
  const token = authHeader.replace('Bearer ', '');
  
  try {
    const payload = await verify(token, c.env.JWT_SECRET);
    if (!payload || !payload.id) {
      return c.json({ error: 'Invalid authentication token' }, 401);
    }
    
    const prisma = new PrismaClient({
      datasourceUrl: c.env.DATABASE_URL,
    }).$extends(withAccelerate());
    
    try {
      const history = await prisma.history.findMany({
        where: { userId: payload.id },
        orderBy: { Date: 'desc' }
      });
      
      return c.json({ history });
    } finally {
      await prisma.$disconnect();
    }
  } catch (error) {
    console.error('Error fetching user history:', error);
    return c.json({ error: 'Failed to fetch history' }, 500);
  }
});

// Helper function to create FormData
async function createFormData(file: File) {
  const formData = new FormData();
  formData.append('file', new Blob([await file.arrayBuffer()]), file.name);
  return formData;
}

export default app;
