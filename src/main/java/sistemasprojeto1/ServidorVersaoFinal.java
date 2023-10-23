package sistemasprojeto1;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.apache.commons.codec.digest.DigestUtils;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.InputMismatchException;
import java.util.Map;
import java.util.Scanner;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.mindrot.jbcrypt.BCrypt;

public class ServidorVersaoFinal {
	private static final String SECRET_KEY = "AoT3QFTTEkj16rCby/TPVBWvfSQHL3GeEz3zVwEd6LDrQDT97sgDY8HJyxgnH79jupBWFOQ1+7fRPBLZfpuA2lwwHqTgk+NJcWQnDpHn31CVm63Or5c5gb4H7/eSIdd+7hf3v+0a5qVsnyxkHbcxXquqk9ezxrUe93cFppxH4/kF/kGBBamm3kuUVbdBUY39c4U3NRkzSO+XdGs69ssK5SPzshn01axCJoNXqqj+ytebuMwF8oI9+ZDqj/XsQ1CLnChbsL+HCl68ioTeoYU9PLrO4on+rNHGPI0Cx6HrVse7M3WQBPGzOd1TvRh9eWJrvQrP/hm6kOR7KrWKuyJzrQh7OoDxrweXFH8toXeQRD8=";
	private static Map<String, String> users = new HashMap<>();
	private static Map<String, String> users1 = new HashMap<>();
	private static ObjectMapper objectMapper = new ObjectMapper();
	private static int nextUserId = 1;

	public static void main(String[] args) {

		ClientHandler clientHandler1 = new ClientHandler();
		clientHandler1.cadastrarUsuarioAdminEstaticamente("Erick", "admin@utfpr.com", "admin1", "admin");

		Scanner scanner = new Scanner(System.in);
		int PORT;
		try {
			System.out.print("Digite a porta para iniciar o servidor: ");
			PORT = scanner.nextInt();
		} catch (InputMismatchException e) {
			System.err.println("Porta inválida. Certifique-se de que você inseriu um número.");
			return;
		}

		System.out.println("Iniciando servidor na porta: " + PORT);

		ExecutorService executorService = Executors.newFixedThreadPool(4);

		try (ServerSocket serverSocket = new ServerSocket(PORT)) {
			while (true) {
				Socket clientSocket = serverSocket.accept();
				System.out.println("Conexão recebida: " + clientSocket.getInetAddress());

				ClientHandler clientHandler = new ClientHandler(clientSocket);
				executorService.execute(clientHandler);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			executorService.shutdown();
		}
	}

	private static class ClientHandler implements Runnable {
		private Socket clientSocket;

		public ClientHandler() {
		}

		public ClientHandler(Socket clientSocket) {
			this.clientSocket = clientSocket;
		}

		@Override
		public void run() {
			try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
					PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {
				String request;
				while ((request = in.readLine()) != null) {
					System.out
							.println("Mensagem recebida do cliente " + clientSocket.getInetAddress() + ": " + request);
					processRequest(request, out);
				}
			} catch (IOException e) {
				e.printStackTrace();
			} finally {
				try {
					clientSocket.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		private void processRequest(String request, PrintWriter out) throws IOException {
			try {

				Map<String, Object> requestData = objectMapper.readValue(request, Map.class);
				removeNullFields(requestData);

				Map<String, Object> responseData = new HashMap<>();
				String action = ((String) requestData.get("action")).toLowerCase().replaceAll(" ", "-");

				switch (action) {
				case "login":
					handleLogin(requestData, responseData);
					break;
				case "logout":
					handleLogout(requestData, responseData);
					break;
				case "cadastro-usuario":
					handleCadastroUsuario(requestData, responseData);
					break;
				case "autocadastro-usuario":
					handleCadastroUsuarioComum(requestData, responseData);
					break;

				default:
					responseData.put("error", true);
					responseData.put("message", "Ação desconhecida");
				}

				out.println(objectMapper.writeValueAsString(responseData));
			} catch (Exception e) {
				e.printStackTrace();
				Map<String, Object> responseData = new HashMap<>();
				responseData.put("error", true);
				responseData.put("message", "Erro no servidor: " + e.getMessage());
				out.println(objectMapper.writeValueAsString(responseData));
			}
		}

		private void removeNullFields(Map<String, Object> map) {
			map.entrySet().removeIf(entry -> entry.getValue() == null);
			map.forEach((key, value) -> {
				if (value instanceof Map) {
					removeNullFields((Map<String, Object>) value);
				}
			});
		}

		private void cadastrarUsuarioAdminEstaticamente(String nome, String email, String senha, String tipo) {
			Map<String, Object> request = new HashMap<>();
			request.put("action", "cadastro-usuario");
			String userId = generateUserId();
			Map<String, Object> userData = new HashMap<>();
			userData.put("name", nome);
			userData.put("email", email);
			userData.put("password", passwordMD5(senha));
			userData.put("type", tipo);
			String adminToken = createJwt(userId, true);
			userData.put("token", adminToken);
			System.out.println("Token gerado para o administrador: " + adminToken);
			request.put("data", userData);

			Map<String, Object> response = new HashMap<>();
			handleCadastroUsuario(request, response);

		}

		private void handleLogin(Map<String, Object> requestData, Map<String, Object> responseData) {
			Map<String, Object> data = (Map<String, Object>) requestData.get("data");
			String email = (String) data.get("email");
			String senha = (String) data.get("password");

			if (email == null || senha == null) {
				responseData.put("error", true);
				responseData.put("message", "Campos obrigatórios ausentes");
				return;
			}

			if (users.containsKey(email)) {
				String hashedPassword = users.get(email);

				if (BCrypt.checkpw(senha, hashedPassword)) {
					String tipo = users1.get(email);

					if ("admin".equals(tipo)) {
						handleAdminLogin(email, requestData, responseData);
					} else {
						handleCommonUserLogin(email, requestData, responseData);
					}
				} else {
					responseData.put("error", true);
					responseData.put("message", "Falha no login");
				}
			} else {
				responseData.put("error", true);
				responseData.put("message", "E-mail não cadastrado");
			}

		}

		private void handleAdminLogin(String email, Map<String, Object> requestData, Map<String, Object> responseData) {
			boolean isAdmin = true;

			String userId = generateUserId();
			String token = createJwt(userId, isAdmin);
			System.out.println("Tipo do token gerado: Admin");
			responseData.put("action", "login");
			responseData.put("error", false);
			Map<String, Object> dataResponse = new HashMap<>();
			dataResponse.put("token", token);
			dataResponse.put("message", "Login realizado com sucesso");
			responseData.put("data", dataResponse);
		}

		private void handleCommonUserLogin(String email, Map<String, Object> requestData,
				Map<String, Object> responseData) {
			boolean isAdmin = false;

			String userId = generateUserId();
			String token = createJwt(userId, isAdmin);
			System.out.println("Tipo do token gerado: Não Admin");
			responseData.put("action", "login");
			responseData.put("error", false);
			Map<String, Object> dataResponse = new HashMap<>();
			dataResponse.put("token", token);
			dataResponse.put("message", "Login realizado com sucesso");
			responseData.put("data", dataResponse);
		}

		private String generateUserId() {
			return UUID.randomUUID().toString();
		}

		private void handleLogout(Map<String, Object> requestData, Map<String, Object> responseData) {
			responseData.put("action", "logout");
			responseData.put("error", false);
			responseData.put("message", "Logout efetuado com sucesso");
		}

		private void handleCadastroUsuario(Map<String, Object> requestData, Map<String, Object> responseData) {
			try {
				Map<String, Object> data = (Map<String, Object>) requestData.get("data");
				if (data == null) {
					throw new CampoObrigatorioAusenteException("data");
				}
				String nome = (String) data.get("name");
				String email = (String) data.get("email");
				String senha = (String) data.get("password");
				String tipo = (String) data.get("type");
				String token = (String) data.get("token");
				String emailRegex = "^[A-Za-z0-9+_.-]+@(.+)$";
				Pattern pattern = Pattern.compile(emailRegex);
				Matcher matcher = pattern.matcher(email);

				if (nome == null || nome.isEmpty()) {
					throw new CampoObrigatorioAusenteException("name");
				}

				if (email == null || email.isEmpty()) {
					throw new CampoObrigatorioAusenteException("email");
				}

				if (!matcher.matches()) {
					throw new FormatoEmailInvalidoException();
				}

				if (senha == null || senha.isEmpty()) {
					throw new CampoObrigatorioAusenteException("password");
				}

				if (tipo == null || tipo.isEmpty()) {
					throw new CampoObrigatorioAusenteException("type");
				}

				if (senha.length() < 6) {
					throw new SenhaInvalidaException();
				}

				if (token == null || token.isEmpty() || !isAdmin(token)) {
					throw new AcessoNegadoException();
				}

				if (users.containsKey(email)) {
					throw new EmailJaCadastradoException();

				} else {

					String userId = generateUserId();
					String hashedPassword = BCrypt.hashpw(senha, BCrypt.gensalt());
					users.put(email, hashedPassword);
					// users.put(email, passwordMD5(senha));
					users1.put(email, tipo);
					responseData.put("action", "cadastro-usuario");
					responseData.put("error", false);
					responseData.put("message", "Usuário cadastrado com sucesso!");
					String tokenGenerated = createJwt(userId, true);
					responseData.put("token", tokenGenerated);

				}
			} catch (CampoObrigatorioAusenteException | SenhaInvalidaException | EmailJaCadastradoException
					| AcessoNegadoException | FormatoEmailInvalidoException e) {
				responseData.put("action", "cadastro-usuario");
				responseData.put("error", true);
				responseData.put("message", e.getMessage());

			}
		}

		public class FormatoEmailInvalidoException extends Exception {

			public FormatoEmailInvalidoException() {
				super("O formato do endereço de e-mail é inválido.");
			}

			public FormatoEmailInvalidoException(String message) {
				super(message);
			}
		}

		public class CampoObrigatorioAusenteException extends Exception {
			public CampoObrigatorioAusenteException(String campo) {
				super("Campo obrigatório ausente: " + campo);
			}
		}

		public class EmailJaCadastradoException extends Exception {
			public EmailJaCadastradoException() {
				super("Email já cadastrado");
			}
		}

		public class AcessoNegadoException extends Exception {
			public AcessoNegadoException() {
				super("Acesso negado. Somente administradores podem realizar esta ação.");
			}
		}

		public class SenhaInvalidaException extends Exception {
			public SenhaInvalidaException() {
				super("A senha deve ter pelo menos 6 dígitos");
			}
		}

		private String passwordMD5(String password) {
			return DigestUtils.md5Hex(password).toUpperCase();
		}

		public String createJwt(String subject, boolean isAdmin) {
			return Jwts.builder().claim("user_id", subject).claim("admin", isAdmin).setSubject(subject)
					.signWith(SignatureAlgorithm.HS256, SECRET_KEY).compact();
		}

		private void handleCadastroUsuarioComum(Map<String, Object> requestData, Map<String, Object> responseData) {
			try {
				Map<String, Object> data = (Map<String, Object>) requestData.get("data");
				String nome = (String) data.get("name");
				String email = (String) data.get("email");
				String senha = (String) data.get("password");
				String emailRegex = "^[A-Za-z0-9+_.-]+@(.+)$";
				Pattern pattern = Pattern.compile(emailRegex);
				Matcher matcher = pattern.matcher(email);

				if (nome == null || nome.isEmpty()) {
					throw new CampoObrigatorioAusenteException("name");
				}
				if (email == null || email.isEmpty()) {
					throw new CampoObrigatorioAusenteException("email");
				}
				if (senha == null || senha.isEmpty()) {
					throw new CampoObrigatorioAusenteException("password");
				}
				if (senha.length() < 6) {
					throw new SenhaInvalidaException();
				}

				if (!matcher.matches()) {
					throw new FormatoEmailInvalidoException();
				}

				if (users.containsKey(email)) {
					throw new EmailJaCadastradoException();
				} else {
					String hashedPassword = BCrypt.hashpw(senha, BCrypt.gensalt());
					users.put(email, hashedPassword);
					// users.put(email, hashedPassword);
					responseData.put("action", "autocadastro-usuario");
					responseData.put("error", false);
					responseData.put("message", "Usuário cadastrado com sucesso!");
				}

			} catch (CampoObrigatorioAusenteException | SenhaInvalidaException | EmailJaCadastradoException
					| FormatoEmailInvalidoException e) {
				responseData.put("action", "autocadastro-usuario");
				responseData.put("error", true);
				responseData.put("message", e.getMessage());
			}
		}

		private static Jws<Claims> parseToken(String token) {
			return Jwts.parser().setSigningKey(SECRET_KEY).parseClaimsJws(token);
		}

		public static boolean isAdmin(String token) {
			try {
				Jws<Claims> parsedToken = parseToken(token);
				Boolean isAdminClaim = parsedToken.getBody().get("admin", Boolean.class);
				System.out.println("Valor da reivindicação 'admin': " + isAdminClaim);
				return isAdminClaim != null && isAdminClaim;
			} catch (Exception e) {
				e.printStackTrace();
				return false;
			}
		}
	}
}