package sistemasprojeto;

import java.awt.BorderLayout;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.regex.Pattern;

import javax.swing.*;
import org.apache.commons.codec.digest.DigestUtils;
import org.mindrot.jbcrypt.BCrypt;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.Claims;
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

public class ServidorFinal {
    private static final String SECRET_KEY = "AoT3QFTTEkj16rCby/TPVBWvfSQHL3GeEz3zVwEd6LDrQDT97sgDY8HJyxgnH79jupBWFOQ1+7fRPBLZfpuA2lwwHqTgk+NJcWQnDpHn31CVm63Or5c5gb4H7/eSIdd+7hf3v+0a5qVsnyxkHbcxXquqk9ezxrUe93cFppxH4/kF/kGBBamm3kuUVbdBUY39c4U3NRkzSO+XdGs69ssK5SPzshn01axCJoNXqqj+ytebuMwF8oI9+ZDqj/XsQ1CLnChbsL+HCl68ioTeoYU9PLrO4on+rNHGPI0Cx6HrVse7M3WQBPGzOd1TvRh9eWJrvQrP/hm6kOR7KrWKuyJzrQh7OoDxrweXFH8toXeQRD8=";
    private static Map<String, UserData> users = new HashMap<>();
    private static ObjectMapper objectMapper = new ObjectMapper();
    private static JTextArea textArea;
    private int PORT;

    public ServidorFinal() {
        JFrame frame = new JFrame("Servidor");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 400);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(2, 1));

        JButton startButton = new JButton("Iniciar Servidor");
        panel.add(startButton);

        textArea = new JTextArea();
        textArea.setEditable(false);
        panel.add(new JScrollPane(textArea));

        frame.add(panel, BorderLayout.CENTER);

        startButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String portStr = JOptionPane.showInputDialog(frame, "Digite a porta para iniciar o servidor:");
                try {
                    PORT = Integer.parseInt(portStr);
                   
                    new Thread(() -> startServer()).start();
                } catch (NumberFormatException ex) {
                    JOptionPane.showMessageDialog(frame, "Porta inválida. Certifique-se de que você inseriu um número.");
                }
            }
        });

        frame.setVisible(true);
    }
    
    private static void appendMessageToUI(String message) {
        SwingUtilities.invokeLater(() -> textArea.append(message + "\n"));
    }
    
    private static void showClientResponse(String response) {
        appendMessageToUI("Resposta para o cliente: " + response);
    }
    
    
    private static void showClientAlert(String message) {
        SwingUtilities.invokeLater(() -> {
            textArea.append("Alerta do cliente: " + message + "\n");
            JOptionPane.showMessageDialog(null, message, "Alerta do Cliente", JOptionPane.INFORMATION_MESSAGE);
        });
    }


    public void startServer() {
        ClientHandler clientHandler1 = new ClientHandler();
        clientHandler1.cadastrarUsuarioAdminEstaticamente("Erick", "admin@utfpr.com", "admin1", "admin");

        textArea.append("Iniciando servidor na porta: " + PORT + "\n");

        ExecutorService executorService = Executors.newFixedThreadPool(4);

        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            appendMessageToUI("Aguardando conexões na porta: " + PORT);
            textArea.append("Aguardando conexões...\n");
            while (true) {
                Socket clientSocket = serverSocket.accept();

                appendMessageToUI("Conexão recebida: " + clientSocket.getInetAddress());
                System.out.println("Conexão recebida: " + clientSocket.getInetAddress());
                textArea.append("Conexão recebida: " + clientSocket.getInetAddress() + "\n");

                ClientHandler clientHandler = new ClientHandler(clientSocket);
                executorService.execute(clientHandler);
            }
        } catch (IOException e) {
            textArea.append("Erro ao iniciar o servidor: " + e.getMessage() + "\n");
            e.printStackTrace();
        } finally {
            executorService.shutdown();
        }
    }
    
    

    private static class ClientHandler implements Runnable {
        private Socket clientSocket;
        private ServidorFinal parentChaos;
        private static int userIdCounter = 1;

        public ClientHandler() {
        }

        public ClientHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }
        
        public ClientHandler(ServidorFinal parentChaos, Socket clientSocket) {
            this.parentChaos = parentChaos; 
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            try (BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
                 PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true)) {
                String request;
                while ((request = in.readLine()) != null) {
                    System.out.println("Mensagem recebida do cliente " + clientSocket.getInetAddress() + ": " + request);
                    appendMessageToUI("Mensagem recebida do cliente " + clientSocket.getInetAddress() + ": " + request);
                    showClientAlert("Mensagem do Cliente:\n" + request);
                    processRequest(request, out);
                 
                   // parentChaos.appendMessageToUI("Mensagem recebida do cliente " + clientSocket.getInetAddress() + ": " + request);
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
                    case "pedido-edicao-usuario":
                        handlePedidoEdicaoUsuario(requestData, responseData);
                        break;
                    case "listar-usuarios":
                        handleListarUsuarios(requestData, responseData);
                        break;
                    case "excluir-usuario":
                    	handleExcluirUsuario(requestData, responseData);
                    	break;
                    	
                    case "pedido-proprio-usuario":
                        handlePedidoProprioUsuario(requestData, responseData);
                        break;
                    case "excluir-proprio-usuario":
                    	handleExcluirProprioUsuario(requestData, responseData);
                    	break;
                    case "edicao-usuario":
                        handleEdicaoUsuario(requestData, responseData);
                        break;      
                    case "autoedicao-usuario":
                    	handleAutoEdicaoUsuario(requestData, responseData);
                        break;

                    default:
                        responseData.put("error", true);
                        responseData.put("message", "Ação desconhecida");
                }

                out.println(objectMapper.writeValueAsString(responseData));
              //  showClientResponse(objectMapper.writeValueAsString(responseData));
                
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
        
        private void handleAutoEdicaoUsuario(Map<String, Object> requestData, Map<String, Object> responseData) {
            Map<String, Object> data = (Map<String, Object>) requestData.get("data");
            String token = (String) data.get("token");
            String userId = getUserIdFromToken(token);
            UserData user = getUserById(userId);

            if (user != null) {
                String oldEmail = user.getEmail(); // Salve o email antigo
                user.setName((String) data.get("name"));
                user.setEmail((String) data.get("email"));

                if (data.get("password") != null) {
                    String senha = (String) data.get("password");
                    user.setPassword(BCrypt.hashpw(senha, BCrypt.gensalt()));
                }
                // user.setType((String) data.get("type"));

                users.remove(oldEmail);
                
                users.put(user.getEmail(), user);

                responseData.put("action", "autoedicao-usuario");
                responseData.put("error", false);
                responseData.put("message", "Usuário atualizado com sucesso!");
            } else {
                responseData.put("action", "autoedicao-usuario");
                responseData.put("error", true);
                responseData.put("message", "Usuário não encontrado.");
            }
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
            System.out.println("ID: " + userId); 

            Map<String, Object> response = new HashMap<>();
            handleCadastroUsuario(request, response);
        }
       //Arrumaisso aqui compara o user_id com o id como vc mudou e da certo, eu acho kkkkkk
		private void handleExcluirUsuario(Map<String, Object> requestData, Map<String, Object> responseData) {
			Map<String, Object> data = (Map<String, Object>) requestData.get("data");
			String token = (String) data.get("token");
			String userId = (String) data.get("user_id");

			if (!isAdmin(token)) {
				responseData.put("action", "excluir-usuario");
				responseData.put("error", true);
				responseData.put("message", "Acesso negado. Somente administradores podem excluir usuários.");
				return;
			}

			List<UserData> usersToKeep = new ArrayList<>();
			
			for (UserData user : users.values()) {
				if (!user.getUserId().equals(userId)) {
					usersToKeep.add(user);
				}
			}
	
			users.clear();

			for (UserData user : usersToKeep) {
				users.put(user.getEmail(), user);
			}

			responseData.put("action", "excluir-usuario");
			responseData.put("error", false);
			responseData.put("message", "Usuário removido com sucesso.");
			System.out.println("Usuário removido com sucesso.");
		}
		
		private void handleExcluirProprioUsuario(Map<String, Object> requestData, Map<String, Object> responseData) {
		    Map<String, Object> data = (Map<String, Object>) requestData.get("data");
		    String token = (String) data.get("token");

		    if (token == null || token.isEmpty()) {
		        responseData.put("action", "excluir-proprio-usuario");
		        responseData.put("error", true);
		        responseData.put("message", "Token de autenticação ausente");
		        return;
		    }

		   
		    String userId = getUserIdFromToken(token);

		    if (userId == null || userId.isEmpty()) {
		        responseData.put("action", "excluir-proprio-usuario");
		        responseData.put("error", true);
		        responseData.put("message", "ID do usuário não encontrado no token");
		        return;
		    }

		    if (removeUserById(userId)) {
		        responseData.put("action", "excluir-proprio-usuario");
		        responseData.put("error", false);
		        responseData.put("message", "Usuário removido com sucesso.");
		    } else {
		        responseData.put("action", "excluir-proprio-usuario");
		        responseData.put("error", true);
		        responseData.put("message", "Erro ao excluir o usuário.");
		    }
		}

		private boolean removeUserById(String userId) {
		    for (String email : users.keySet()) {
		        UserData user = users.get(email);
		        if (user.getUserId().equals(userId)) {
		            users.remove(email);
		            return true;
		        }
		    }
		    return false;
		}
		
		private void handleEdicaoUsuario(Map<String, Object> requestData, Map<String, Object> responseData) {
		    Map<String, Object> data = (Map<String, Object>) requestData.get("data");
		    String token = (String) data.get("token");
		    String userId = (String) data.get("user_id");

		    if (isAdmin(token)) {
		        UserData user = getUserById(userId);

		        if (user != null) {
		            String oldEmail = user.getEmail(); // Salve o email antigo
		            user.setName((String) data.get("name"));
		            user.setEmail((String) data.get("email"));

		            if (data.get("password") != null) {
		                String senha = (String) data.get("password");
		                user.setPassword(BCrypt.hashpw(senha, BCrypt.gensalt()));
		            }
		            user.setType((String) data.get("type"));

		            users.remove(oldEmail);
		            
		            users.put(user.getEmail(), user);

		            responseData.put("action", "edicao-usuario");
		            responseData.put("error", false);
		            responseData.put("message", "Usuário atualizado com sucesso!");
		        } else {
		            responseData.put("action", "edicao-usuario");
		            responseData.put("error", true);
		            responseData.put("message", "Usuário não encontrado.");
		        }
		    } else {
		        responseData.put("action", "edicao-usuario");
		        responseData.put("error", true);
		        responseData.put("message", "Acesso negado. Somente administradores podem editar usuários.");
		    }
		}
		
        private void handlePedidoEdicaoUsuario(Map<String, Object> requestData, Map<String, Object> responseData) {
        	Map<String, Object> data = (Map<String, Object>) requestData.get("data");
            String token = (String) data.get("token");
            String userId = (String) data.get("user_id");
            
            if (token == null || token.isEmpty() || !isAdmin(token)) {
                responseData.put("action", "pedido-edicao-usuario");
                responseData.put("error", true);
                responseData.put("message", "Acesso negado. Somente administradores podem realizar esta ação.");
            } else {
            
                UserData user = getUserById(userId);
                if (user != null) {
                    responseData.put("action", "pedido-edicao-usuario");
                    responseData.put("error", false);
                    responseData.put("message", "Sucesso");
                    Map<String, Object> userData = new HashMap<>();
                    userData.put("id", user.getUserId());
                    userData.put("name", user.getName());
                    userData.put("type", user.getType());
                    userData.put("email", user.getEmail());
                    responseData.put("data", Collections.singletonMap("user", userData));
                } else {
                    responseData.put("action", "pedido-edicao-usuario");
                    responseData.put("error", true);
                    responseData.put("message", "Usuário não encontrado");
                }
            }
        }
        
        private void handlePedidoProprioUsuario(Map<String, Object> requestData, Map<String, Object> responseData) {
            Map<String, Object> data = (Map<String, Object>) requestData.get("data");
            String token = (String) data.get("token");

            if (token == null || token.isEmpty()) {
                responseData.put("action", "pedido-proprio-usuario");
                responseData.put("error", true);
                responseData.put("message", "Token de autenticação ausente");
                return;
            }

            String userId = getUserIdFromToken(token);

            if (userId == null || userId.isEmpty()) {
                responseData.put("action", "pedido-proprio-usuario");
                responseData.put("error", true);
                responseData.put("message", "ID do usuário não encontrado no token");
                return;
            }

          
            UserData user = getUserById(userId);

            if (user != null) {
                responseData.put("action", "pedido-proprio-usuario");
                responseData.put("error", false);
                responseData.put("message", "Sucesso");
                Map<String, Object> userData = new HashMap<>();
                userData.put("id", user.getUserId());
                userData.put("name", user.getName());
                userData.put("type", user.getType());
                userData.put("email", user.getEmail());
                responseData.put("data", Collections.singletonMap("user", userData));
            } else {
                responseData.put("action", "pedido-proprio-usuario");
                responseData.put("error", true);
                responseData.put("message", "Usuário não encontrado");
            }
        }

        private String getUserIdFromToken(String token) {
            try {
                Jws<Claims> parsedToken = parseToken(token);
                String userId = parsedToken.getBody().get("id", String.class);
                return userId;
            } catch (Exception e) {
                e.printStackTrace();
                return null;
            }
        }

        
        private void handleListarUsuarios(Map<String, Object> requestData, Map<String, Object> responseData) {
        	Map<String, Object> data = (Map<String, Object>) requestData.get("data");
            String token = (String) data.get("token");
            if (!isAdmin(token)) {
                responseData.put("action", "listar-usuarios");
                responseData.put("error", true);
                responseData.put("message", "Acesso negado. Somente administradores podem realizar esta ação.");
                return;
            }

            List<Map<String, Object>> userList = new ArrayList<>();

       
            for (UserData user : users.values()) {
                Map<String, Object> userMap = new HashMap<>();
                userMap.put("id", user.getUserId());
                userMap.put("name", user.getName());
                userMap.put("type", user.getType());
                userMap.put("email", user.getEmail());
                userList.add(userMap);
            }

            responseData.put("action", "listar-usuarios");
            responseData.put("error", false);
            responseData.put("message", "Sucesso");
            responseData.put("data", Collections.singletonMap("users", userList));
        }

        private UserData getUserById(String userId) {
            for (UserData user : users.values()) {
                if (user.getUserId().equals(userId)) {
                    return user;
                }
            }
            return null;
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
            	UserData userData = users.get(email);
                String hashedPassword = userData.getPassword();
                
                //userData.put("email", user.getEmail());
                if (BCrypt.checkpw(senha, hashedPassword)) {
                	String tipo = userData.getType();

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

            UserData userData = users.get(email); 
            if (userData != null) {
                String userId = userData.getUserId();
                String token = createJwt(userId, isAdmin);
                System.out.println("Tipo do token gerado: Admin");
                responseData.put("action", "login");
                responseData.put("message", "Login Confirmado");
                responseData.put("error", false);
                Map<String, Object> dataResponse = new HashMap<>();
                dataResponse.put("token", token);
                responseData.put("data", dataResponse);
                System.out.println("Enviado para o cliente: " + responseData);
                System.out.println("ID: " + userId);
            } else {
                
                responseData.put("action", "login");
                responseData.put("error", true);
                responseData.put("message", "Usuário não encontrado");
            }
        }

        private void handleCommonUserLogin(String email, Map<String, Object> requestData, Map<String, Object> responseData) {
            boolean isAdmin = false;

            UserData userData = users.get(email); 
            if (userData != null) {
                String userId = userData.getUserId();
                String token = createJwt(userId, isAdmin);
                System.out.println("Tipo do token gerado: Não Admin");
                responseData.put("action", "login");
                responseData.put("error", false);
                responseData.put("message", "Login realizado com sucesso");
                Map<String, Object> dataResponse = new HashMap<>();
                dataResponse.put("token", token);
                responseData.put("data", dataResponse);
                System.out.println("Enviado para o cliente: " + responseData);
            } else {
               
                responseData.put("action", "login");
                responseData.put("error", true);
                responseData.put("message", "Usuário não encontrado");
            }
        }

        private String generateUserId() {
            String userId = String.valueOf(userIdCounter);
            userIdCounter++;
            return userId;
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

                     UserData userData = new UserData();
                     userData.setName(nome);
                     userData.setEmail(email);
                     userData.setPassword(hashedPassword);
                     userData.setType(tipo);
                     userData.setToken(createJwt(userId, true));
                     userData.setUserId(userId);

                     users.put(email, userData);

                     responseData.put("action", "cadastro-usuario");
                     responseData.put("error", false);
                     responseData.put("message", "Usuário cadastrado com sucesso!");
                     responseData.put("token", userData.getToken());
                     System.out.println("ID: " + userId); 
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
        
        private void handleCadastroUsuarioComum(Map<String, Object> requestData, Map<String, Object> responseData) {
			try {
				Map<String, Object> data = (Map<String, Object>) requestData.get("data");
				String nome = (String) data.get("name");
				String email = (String) data.get("email");
				String senha = (String) data.get("password");
				String emailRegex = "^[A-Za-z0-9+_.-]+@(.+)$";
				Pattern pattern = Pattern.compile(emailRegex);
				Matcher matcher = pattern.matcher(email);
				String userId = generateUserId();

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
                    UserData userData = new UserData();
                    userData.setName(nome);
                    userData.setEmail(email);
                    userData.setPassword(hashedPassword);
                    userData.setToken(createJwt(userId, false));
                    userData.setType("user");
                    userData.setUserId(userId);
                    users.put(email, userData);
                    responseData.put("action", "autocadastro-usuario");
                    responseData.put("error", false);
                    responseData.put("message", "Usuário cadastrado com sucesso!");
                    System.out.println("ID: " + userId); 
				}

			} catch (CampoObrigatorioAusenteException | SenhaInvalidaException | EmailJaCadastradoException
					| FormatoEmailInvalidoException e) {
				responseData.put("action", "autocadastro-usuario");
				responseData.put("error", true);
				responseData.put("message", e.getMessage());
			}
		}

        private String passwordMD5(String password) {
            return DigestUtils.md5Hex(password).toUpperCase();
        }

        public String createJwt(String subject, boolean isAdmin) {
            return Jwts.builder()
                    .claim("id", subject)
                    .claim("admin", isAdmin)
                    .setSubject(subject)
                    .signWith(SignatureAlgorithm.HS256, SECRET_KEY)
                    .compact();
        }

        private static Jws<Claims> parseToken(String token) {
            return Jwts.parser()
                    .setSigningKey(SECRET_KEY)
                    .parseClaimsJws(token);
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
        
        public static void main(String[] args) {
            SwingUtilities.invokeLater(new Runnable() {
                @Override
                public void run() {
                    new ServidorFinal();
                }
            });
        }
        
        
    }   

    public static class UserData {
        private String name;
        private String email;
        private String password;
        private String type;
        private String token;
        private String userId;

        public String getName() {
            return name;
        }

        public void setName(String name) {
            this.name = name;
        }

        public String getEmail() {
            return email;
        }

        public void setEmail(String email) {
            this.email = email;
        }

        public String getPassword() {
            return password;
        }

        public void setPassword(String password) {
            this.password = password;
        }

        public String getType() {
            return type;
        }

        public void setType(String type) {
            this.type = type;
        }

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }

        public String getUserId() {
            return userId;
        }

        public void setUserId(String userId) {
            this.userId = userId;
        }
    }

    
}
        
    