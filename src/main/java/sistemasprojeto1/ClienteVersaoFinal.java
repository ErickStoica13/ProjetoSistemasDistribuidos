package sistemasprojeto1;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import org.apache.commons.codec.digest.DigestUtils;
import com.fasterxml.jackson.databind.ObjectMapper;

public class ClienteVersaoFinal {
	private static ObjectMapper objectMapper = new ObjectMapper();

	public static void main(String[] args) {
		Scanner scanner = new Scanner(System.in);
		String userCommand;

		System.out.print("Digite o endereço IP do servidor: ");
		String serverIP = scanner.nextLine();

		System.out.print("Digite o número da porta do servidor: ");
		int serverPort = Integer.parseInt(scanner.nextLine());

		String userToken = null;

		try (Socket socket = new Socket(serverIP, serverPort);
				BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
				PrintWriter out = new PrintWriter(socket.getOutputStream(), true)) {

			System.out.println("Conexão estabelecida com o servidor " + serverIP + ":" + serverPort);

			while (true) {
				System.out.println("Escolha uma ação:");
				System.out.println("1 - Login");
				System.out.println("2 - Logout");
				System.out.println("3 - Cadastro de Usuário (Admin)");
				System.out.println("4 - Cadastro de Usuário (Comum)");
				System.out.println("0 - Sair");

				int choice;
				try {
					choice = Integer.parseInt(scanner.nextLine());
				} catch (NumberFormatException e) {
					System.out.println("Opção inválida. Digite uma opção válida.");
					continue;
				}

				if (choice == 0) {
					break;
				}

				Map<String, Object> request = null;

				switch (choice) {
				case 1:
					String email, password;
					System.out.print("Digite o email: ");
					email = scanner.nextLine();
					System.out.print("Digite a senha: ");
					password = scanner.nextLine();
					request = createLoginRequest(email, password);
					break;
				case 2:
					request = createLogoutRequest(userToken);
					sendRequest(out, request);
					userToken = processResponse(in);
					break;
				case 3:
					String nome, novoEmail, novaSenha, tipo;
					System.out.print("Digite o nome: ");
					nome = scanner.nextLine();
					System.out.print("Digite o email: ");
					novoEmail = scanner.nextLine();
					while (true) {
						System.out.print("Digite a senha: ");
						novaSenha = scanner.nextLine();

						if (novaSenha.length() < 6) {
							System.out.println("A senha deve ter pelo menos 6 caracteres. Tente novamente.");
						} else {
							break;
						}
					}

					tipo = "admin";
					request = createCadastroUsuarioRequest(userToken, nome, novoEmail, novaSenha, tipo);
					break;
				case 4:
					String nome1, novoEmail1, novaSenha1;
					System.out.print("Digite o nome: ");
					nome1 = scanner.nextLine();
					System.out.print("Digite o email: ");
					novoEmail1 = scanner.nextLine();
					System.out.print("Digite a senha: ");
					novaSenha1 = scanner.nextLine();
					request = createCadastroUsuarioComumRequest(nome1, novoEmail1, novaSenha1);
					break;
				default:
					System.out.println("Opção inválida. Digite uma opção válida.");
				}

				if (request != null) {
					sendRequest(out, request);
					userToken = processResponse(in);
				}
			}
		} catch (IOException e) {
			System.out.println("Servidor inexistente ou não disponível.");
		}
	}

	private static void sendRequest(PrintWriter out, Map<String, Object> request) {
		try {
			String jsonRequest = objectMapper.writeValueAsString(request);
			out.println(jsonRequest);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static String processResponse(BufferedReader in) {
		try {
			String jsonResponse = in.readLine();
			Map<String, Object> response = objectMapper.readValue(jsonResponse, Map.class);
			System.out.println("Resposta do servidor: " + response);

			if (response.containsKey("error")) {
				Object errorValue = response.get("error");

				if (errorValue instanceof Boolean && (Boolean) errorValue) {
					String message = (String) response.get("message");
					System.out.println("Erro: " + message);
				}
			}

			if (response.containsKey("data") && response.get("data") instanceof Map) {
				Map<String, Object> responseData = (Map<String, Object>) response.get("data");
				if (responseData.containsKey("token")) {
					String token = (String) responseData.get("token");
					System.out.println("Token recebido: " + token);
					return token;
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		}

		return null;
	}

	public static String passwordMD5(String password) {
		return DigestUtils.md5Hex(password).toUpperCase();
	}

	private static Map<String, Object> createCadastroUsuarioRequest(String token, String nome, String email,
			String senha, String tipo) {
		Map<String, Object> request = new HashMap<>();
		request.put("action", "cadastro-usuario");
		Map<String, Object> data = new HashMap<>();
		data.put("token", token);
		data.put("name", nome);
		data.put("email", email);
		data.put("password", passwordMD5(senha));
		data.put("type", tipo);
		request.put("data", data);
		return request;
	}

	private static Map<String, Object> createLoginRequest(String email, String senha) {
		Map<String, Object> request = new HashMap<>();
		request.put("action", "login");
		Map<String, Object> data = new HashMap<>();
		data.put("email", email);
		data.put("password", passwordMD5(senha));
		request.put("data", data);
		return request;
	}

	private static Map<String, Object> createLogoutRequest(String token) {
		Map<String, Object> request = new HashMap<>();
		request.put("action", "logout");
		Map<String, Object> data = new HashMap<>();
		data.put("token", token);
		request.put("data", data);
		return request;
	}

	private static Map<String, Object> createCadastroUsuarioComumRequest(String nome, String email, String senha) {
		Map<String, Object> request = new HashMap<>();
		request.put("action", "autocadastro-usuario");
		Map<String, Object> data = new HashMap<>();
		data.put("name", nome);
		data.put("email", email);
		data.put("password", passwordMD5(senha));
		request.put("data", data);
		return request;
	}

}
