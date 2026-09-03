using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using TDSProxy.Authentication;
using TDSProxy.Configuration;

namespace TDSProxy
{
	class TDSListener : IDisposable
	{
		#region Log4Net
		static readonly log4net.ILog log = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);
		#endregion

		readonly TDSProxyService _service;
		readonly TcpListener _tcpListener;
		readonly string _name;
		volatile bool _stopped;

		internal readonly X509Certificate Certificate;
		internal readonly ListenerTlsConfig ListenerTlsConfig;
		internal readonly ServerTlsConfig ServerTlsConfig;
		internal readonly SslProtocols EnabledSslProtocols;

		public TDSListener(TDSProxyService service, ListenerConfig listenerConfig, ServerConfig serverConfig, string name)
		{
			_name = name;
			_service = service;
			ListenerTlsConfig = listenerConfig.Tls;
			ServerTlsConfig = serverConfig.Tls;

			// Resolve server address
			IPAddress forwardAddress;
			if (!IPAddress.TryParse(serverConfig.Host, out forwardAddress))
			{
				try
				{
					var insideAddresses = Dns.GetHostAddresses(serverConfig.Host);
					if (0 == insideAddresses.Length)
					{
						log.ErrorFormat("Unable to resolve server host=\"{0}\" for listener {1}", serverConfig.Host, name);
						_stopped = true;
						return;
					}
					forwardAddress = insideAddresses.First();
				}
				catch (Exception ex)
				{
					log.ErrorFormat("DNS lookup failed for server host=\"{0}\" for listener {1}: {2}", serverConfig.Host, name, ex.Message);
					_stopped = true;
					return;
				}
			}
			ForwardTo = new IPEndPoint(forwardAddress, serverConfig.Port);

			// Parse listener bind address
			IPAddress bindAddress = IPAddress.Any;
			if (!string.IsNullOrEmpty(listenerConfig.Host) && listenerConfig.Host != "0.0.0.0")
			{
				if (!IPAddress.TryParse(listenerConfig.Host, out bindAddress))
				{
					log.WarnFormat("Invalid bind address '{0}' for listener {1}, using 0.0.0.0", listenerConfig.Host, name);
					bindAddress = IPAddress.Any;
				}
			}
			var bindToEP = new IPEndPoint(bindAddress, listenerConfig.Port);

			// No authenticators in simplified config
			_authenticators = Array.Empty<Lazy<IAuthenticator>>();

			// Load SSL certificate if TLS is enabled
			if (listenerConfig.Tls?.Enabled == true)
			{
				try
				{
					Certificate = LoadCertificateFromFile(listenerConfig.Tls.CertificatePath, listenerConfig.Tls.CertificatePassword, name);
					if (Certificate == null)
					{
						log.Warn($"Failed to load SSL certificate for listener {name}. Running without TLS.");
					}
					else
					{
						EnabledSslProtocols = ParseSslProtocols(listenerConfig.Tls.Protocols);
					}
				}
				catch (Exception e)
				{
					log.Error($"Failed to load SSL certificate for listener {name}", e);
					Certificate = null;
				}
			}
			else
			{
				log.Info($"TLS not enabled for listener {name}. Running without TLS.");
				Certificate = null;
			}

			_tcpListener = new TcpListener(bindToEP);
			_tcpListener.Start();
			_tcpListener.BeginAcceptTcpClient(AcceptConnection, _tcpListener);

			_service.AddListener(this);

			var certInfo = Certificate != null
				? $"TLS enabled (cert: {Certificate.Subject}, expires: {Certificate.GetExpirationDateString()}, protocols: {listenerConfig.Tls?.Protocols})"
				: "TLS disabled";
			var serverTlsInfo = serverConfig.Tls?.Enabled == true
				? $"Server TLS enabled (validate: {serverConfig.Tls.ValidateCertificate}, trust: {serverConfig.Tls.TrustServerCertificate})"
				: "Server TLS disabled";

			log.InfoFormat(
				"Listener {0}: {1} -> {2} ({3}; {4})",
				name,
				bindToEP,
				ForwardTo,
				certInfo,
				serverTlsInfo);
		}

		private X509Certificate2 LoadCertificateFromFile(string filePath, string password, string listenerName)
		{
			if (string.IsNullOrEmpty(filePath))
			{
				throw new InvalidOperationException($"Certificate path not specified for listener {listenerName}");
			}

			if (!Path.IsPathRooted(filePath))
			{
				filePath = Path.Combine(AppContext.BaseDirectory, filePath);
			}

			if (!File.Exists(filePath))
			{
				throw new FileNotFoundException($"Certificate file not found: {filePath}", filePath);
			}

			log.DebugFormat("Loading SSL certificate from file: {0}", filePath);

			if (string.IsNullOrEmpty(password))
			{
				return new X509Certificate2(filePath);
			}
			else
			{
				return new X509Certificate2(filePath, password, X509KeyStorageFlags.PersistKeySet);
			}
		}

#pragma warning disable CS0618, SYSLIB0039 // Intentionally supporting legacy TLS versions for compatibility
		private SslProtocols ParseSslProtocols(string protocols)
		{
			if (string.IsNullOrEmpty(protocols))
			{
				return SslProtocols.Tls12 | SslProtocols.Tls13;
			}

			SslProtocols result = SslProtocols.None;
			foreach (var protocol in protocols.Split(','))
			{
				var trimmed = protocol.Trim();
				switch (trimmed.ToLowerInvariant())
				{
					case "tls":
					case "tls10":
					case "tls1.0":
						result |= SslProtocols.Tls;
						break;
					case "tls11":
					case "tls1.1":
						result |= SslProtocols.Tls11;
						break;
					case "tls12":
					case "tls1.2":
						result |= SslProtocols.Tls12;
						break;
					case "tls13":
					case "tls1.3":
						result |= SslProtocols.Tls13;
						break;
					default:
						log.WarnFormat("Unknown TLS protocol: {0}", trimmed);
						break;
				}
			}

			return result == SslProtocols.None ? SslProtocols.Tls12 | SslProtocols.Tls13 : result;
		}
#pragma warning restore CS0618, SYSLIB0039

		private Lazy<IAuthenticator>[] _authenticators;

		public IEnumerable<Lazy<IAuthenticator>> Authenticators =>
			!_stopped
				? (Lazy<IAuthenticator>[])_authenticators.Clone()
				: throw new ObjectDisposedException(nameof(TDSListener));

		public IPEndPoint ForwardTo { get; }

		private void AcceptConnection(IAsyncResult result)
		{
			TcpClient readClient;

			try
			{
				readClient = ((TcpListener)result.AsyncState).EndAcceptTcpClient(result);

				log.InfoFormat("Accepted connection from {0} on {1}, will forward to {2}", readClient.Client.RemoteEndPoint, readClient.Client.LocalEndPoint, ForwardTo);

				if (_service?.StopRequested == true)
				{
					log.Info("Service was ending, closing connection and returning.");
					readClient.Close();
					return;
				}
			}
			catch (ObjectDisposedException)
			{
				/* We're shutting down, ignore */
				return;
			}
			catch (Exception e)
			{
				log.Fatal("Error accepting connection.", e);
				return;
			}
			finally
			{
				ResumeAccepting();
			}

			// Setting up the connection dials the far server, and that dial blocks. It has to happen
			// after the listener is accepting again: a server that swallows SYNs takes the connect
			// timeout to fail, and until this method returned, that was equally how long every other
			// client sat in the backlog waiting to be accepted.
			try
			{
				new TDSConnection(_service, this, readClient, ForwardTo);
			}
			catch (Exception e)
			{
				log.Fatal("Error in AcceptConnection.", e);
				try
				{
					readClient.Close();
				}
				catch (Exception closeError)
				{
					log.Error("Error closing a connection that could not be set up.", closeError);
				}
			}
		}

		void ResumeAccepting()
		{
			if (_stopped)
				return;

			try
			{
				_tcpListener?.BeginAcceptTcpClient(AcceptConnection, _tcpListener);
			}
			catch (ObjectDisposedException) { /* We're shutting down, ignore */ }
		}

		public void Dispose()
		{
			if (!_stopped)
			{
				_stopped = true;
				_service?.RemoveListener(this);
				_tcpListener?.Stop();
				_authenticators = null;
			}
		}
	}
}
