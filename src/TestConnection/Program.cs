using System;
using Microsoft.Data.SqlClient;

namespace TestConnection
{
	static class Program
	{
		// A manual smoke test: point it at a proxy listener and confirm a real TDS
		// session survives the round trip. Not part of the published image — the
		// Dockerfile builds TDSProxy.csproj alone — and not run by CI, which has no
		// SQL Server to talk to.
		//
		// The connection string is read from the environment rather than compiled in.
		// It previously carried a live-looking one (an internal host, a domain user
		// and a password) inherited from upstream, which is not something a public
		// repository should hold regardless of whether the host still answers.
		const string ConnectionStringVariable = "TDSPROXY_TEST_CONNECTION_STRING";

		static int Main()
		{
			var connectionString = Environment.GetEnvironmentVariable(ConnectionStringVariable);
			if (string.IsNullOrWhiteSpace(connectionString))
			{
				Console.Error.WriteLine(
					$"Set {ConnectionStringVariable} to the connection string to test, e.g.\n" +
					$"  export {ConnectionStringVariable}=" +
					"'Server=127.0.0.1,1435;Database=YourDb;User Id=you;Password=...;TrustServerCertificate=true'\n" +
					"Point Server at the proxy's listener, not at SQL Server directly.");
				return 2;
			}

			var query = Environment.GetEnvironmentVariable("TDSPROXY_TEST_QUERY") ?? "SELECT 1";

			using var cn = new SqlConnection(connectionString);
			cn.Open();
			while (true)
			{
				using (var cmd = cn.CreateCommand())
				{
					cmd.CommandText = query;
					using var dr = cmd.ExecuteReader();
					while (dr.Read())
					{
						for (int i = 0; i < dr.FieldCount; i++)
							Console.Write("{0}\t", dr.GetValue(i));
						Console.WriteLine();
					}
				}

				Console.WriteLine("Press Esc to quit, any other key to repeat.");
				if (Console.ReadKey(true).Key == ConsoleKey.Escape)
					break;
			}

			return 0;
		}
	}
}
