package sistemasprojeto;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.codec.digest.DigestUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

public class ClienteFinal {

    private static final ObjectMapper objectMapper = new ObjectMapper();

    private JFrame frame;
    private JTextField serverIPField;
    private JTextField serverPortField;
    private JTextArea logTextArea;
    private JButton connectButton;
    private JButton loginButton;
    private JButton logoutButton;
    private JButton cadastroAdminButton;
    private JButton cadastroComumButton;
    private JButton sairButton;
    private JButton pedidoEdicaoUsuarioButton;
    private JButton listarUsuariosButton;
    private JButton excluirUsuarioButton;
    private JButton pedidoProprioUsuarioButton;
    private JButton excluirProprioUsuarioButton;
    private JButton alterarDadosUsuarioButton;
    private JButton autoEdicaoUsuarioButton;
    private JButton cadastroComum1Button;

    private Socket socket;
    private PrintWriter out;
    private BufferedReader in;

    private String userToken;

    public ClienteFinal() {
        frame = new JFrame("Cliente");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400, 400);

        JPanel panel = new JPanel();
        panel.setLayout(new GridLayout(3, 2));

        serverIPField = new JTextField(15);
        serverPortField = new JTextField(5);
        connectButton = new JButton("Conectar");
        logTextArea = new JTextArea(10, 30);
        logTextArea.setEditable(false);
        JScrollPane logScrollPane = new JScrollPane(logTextArea);

        loginButton = new JButton("Login");
        logoutButton = new JButton("Logout");
        cadastroAdminButton = new JButton("Cadastro de Usuário (Admin)");
        cadastroComumButton = new JButton("Auto Cadastro de Usuário (Comum)");
        sairButton = new JButton("Sair");
        pedidoEdicaoUsuarioButton = new JButton("Pedido de Edição de Usuário(Admin)");
        listarUsuariosButton = new JButton("Listar Usuários");
        excluirUsuarioButton = new JButton("Excluir Usuário");
        pedidoProprioUsuarioButton = new JButton("Pedido de Dados do Próprio Usuário");
        excluirProprioUsuarioButton = new JButton("Excluir Próprio Usuário");
        alterarDadosUsuarioButton = new JButton("Alterar dados de usuário");
        autoEdicaoUsuarioButton = new JButton("Auto Edição de Usuário");
        cadastroComum1Button = new JButton("Cadastro User Comum"); 


        panel.add(new JLabel("Endereço IP do Servidor:"));
        panel.add(serverIPField);
        panel.add(new JLabel("Número da Porta do Servidor:"));
        panel.add(serverPortField);
        panel.add(new JLabel());
        panel.add(connectButton);

        frame.add(panel, BorderLayout.NORTH);
        frame.add(logScrollPane, BorderLayout.CENTER);

        connectButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                connectToServer();
            }
        });

        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridLayout(3, 2));
        buttonPanel.add(loginButton);
        buttonPanel.add(logoutButton);
        buttonPanel.add(cadastroAdminButton);
        buttonPanel.add(cadastroComumButton);
        buttonPanel.add(sairButton);
        buttonPanel.add(pedidoEdicaoUsuarioButton);
        buttonPanel.add(listarUsuariosButton);
        buttonPanel.add(excluirUsuarioButton);
        buttonPanel.add(pedidoProprioUsuarioButton);
        buttonPanel.add(excluirProprioUsuarioButton);
        buttonPanel.add(alterarDadosUsuarioButton);
        buttonPanel.add(autoEdicaoUsuarioButton);
        buttonPanel.add(cadastroComum1Button);

        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                login();
            }
        });

        logoutButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logout();
            }
        });
        
        pedidoProprioUsuarioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                pedidoProprioUsuario();
            }
        });
        
        autoEdicaoUsuarioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                autoEdicaoUsuario();
            }
        });
        
        alterarDadosUsuarioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                alterarDadosUsuario();
            }
        });
        
        excluirProprioUsuarioButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                excluirProprioUsuario();
            }
        });
        

		pedidoEdicaoUsuarioButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				pedidoEdicaoUsuario();
			}
		});
		
		excluirUsuarioButton.addActionListener(new ActionListener() {
		    @Override
		    public void actionPerformed(ActionEvent e) {
		        excluirUsuario();
		    }
		});

        cadastroAdminButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cadastrarAdmin();
            }
        });
        
        cadastroComum1Button.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
            	cadastrarComum1();
            }
        });

        cadastroComumButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                cadastrarComum();
            }
        });

        sairButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sair();
            }
        });
        
        listarUsuariosButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                listarUsuarios();
            }
        });

        frame.add(buttonPanel, BorderLayout.SOUTH);

        frame.setVisible(true);
    }
    
    

    public void connectToServer() {
        try {
            String serverIP = serverIPField.getText();
            int serverPort = Integer.parseInt(serverPortField.getText());
            socket = new Socket(serverIP, serverPort);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            log("Conexão estabelecida com o servidor " + serverIP + ":" + serverPort);
        } catch (IOException e) {
            log("Servidor inexistente ou não disponível.");
        }
    }
    ////////////////////////////////////////////////////
    public void autoEdicaoUsuario() {
        if (userToken == null) {
            log("Você precisa estar logado como usuário comum para realizar a autoedição de usuário.");
            return;
        }
        String userId = showInputDialog("O userId usuario"); //aqui nao deve ser um novo id, deve ser o id do usuario q deseja ser alterado
        String newName = showInputDialog("Digite o novo nome:");
        String newEmail = showInputDialog("Digite o novo email:");
        String newPassword = showInputDialog("Digite a nova senha (deixe em branco para não alterar):");

        Map<String, Object> request = createAutoEdicaoUsuarioRequest(userToken,userId, newName, newEmail, newPassword);
        sendRequest(out, request);

        String response = processResponse(in);
      
    }
    
    private void showResponseAlert(String message) {
        JOptionPane.showMessageDialog(frame, message, "Resposta do Servidor", JOptionPane.INFORMATION_MESSAGE);
    }
    //////////////////////////////////////
    public void alterarDadosUsuario() {
        if (userToken == null) {
            log("Você precisa estar logado como administrador para alterar os dados do usuário.");
            return;
        }

        String userId = showInputDialog("Digite o ID do usuário que deseja editar:");
        String newName = showInputDialog("Digite o novo nome:");
        String newEmail = showInputDialog("Digite o novo email:");
        String newPassword = showInputDialog("Digite a nova senha (deixe em branco para não alterar):");
        String newType = showInputDialog("Digite o novo tipo de usuário (admin/user):");

        Map<String, Object> request = createAlterarDadosUsuarioRequest(userToken, userId, newName, newEmail, newPassword, newType);
        sendRequest(out, request);

        String response = processResponse(in);
     
    }

    public void login() {
        String email = showInputDialog("Digite o email:");
        String senha = showInputDialog("Digite a senha:");

        Map<String, Object> request = createLoginRequest(email, senha);
        sendRequest(out, request);
        userToken = processResponse(in);
        
        if (userToken != null) {
            log("Login bem-sucedido. Token: " + userToken);
        } else {
            log("Falha no login. Verifique suas credenciais.");
        }
    }
    
    public void excluirProprioUsuario() {
        if (userToken == null) {
            log("Você precisa estar logado para excluir o próprio usuário.");
            return;
        }

        String email = showInputDialog("Digite o seu email:");
        String senha = showInputDialog("Digite a sua senha:");

        Map<String, Object> request = createExcluirProprioUsuarioRequest(userToken, email, senha);
        sendRequest(out, request);

        String response = processResponse(in);
     
    }

    public void logout() {
        if (userToken == null) {
            log("Você não está logado. Não é possível fazer logout.");
        } else {
            Map<String, Object> request = createLogoutRequest(userToken);
            sendRequest(out, request);
            userToken = processResponse(in);
            
            if (userToken == null) {
                log("Logout bem-sucedido.");
            } else {
                log("Falha no logout.");
            }
        }
    }

    public void cadastrarAdmin() {
        String nome = showInputDialog("Digite o nome:");
        String email = showInputDialog("Digite o email:");
        String senha = showInputDialog("Digite a senha:");

        while (senha.length() < 6) {
            senha = showInputDialog("A senha deve ter pelo menos 6 caracteres. Tente novamente:");
        }

        String tipo = "admin";
        Map<String, Object> request = createCadastroUsuarioRequest(userToken, nome, email, senha, tipo);
        sendRequest(out, request);
        userToken = processResponse(in);
        log("Cadastro de usuário (Admin) bem-sucedido.");
       
    }
    
    public void cadastrarComum1() {
        String nome = showInputDialog("Digite o nome:");
        String email = showInputDialog("Digite o email:");
        String senha = showInputDialog("Digite a senha:");

        while (senha.length() < 6) {
            senha = showInputDialog("A senha deve ter pelo menos 6 caracteres. Tente novamente:");
        }

        String tipo = "user";
        Map<String, Object> request = createCadastroUsuarioRequest(userToken, nome, email, senha, tipo);
        sendRequest(out, request);
        userToken = processResponse(in);
        log("Cadastro de usuário (Comum) bem-sucedido.");
       
    }

    public void cadastrarComum() {
        String nome = showInputDialog("Digite o nome:");
        String email = showInputDialog("Digite o email:");
        String senha = showInputDialog("Digite a senha:");

        while (senha.length() < 6) {
            senha = showInputDialog("A senha deve ter pelo menos 6 caracteres. Tente novamente:");
        }

        Map<String, Object> request = createCadastroUsuarioComumRequest(nome, email, senha);
        sendRequest(out, request);
        userToken = processResponse(in);
        log("Cadastro de usuário (Comum) bem-sucedido. Token: " + userToken);
       
    }
    
    public void pedidoEdicaoUsuario() {
        if (userToken == null) {
            log("Você precisa estar logado para fazer um pedido de edição de usuário.");
            return;
        }

        String userId = showInputDialog("Digite o ID do usuário que deseja editar:");
        
        Map<String, Object> request = createPedidoEdicaoUsuarioRequest(userToken, userId);
        sendRequest(out, request);
        
        String response = processResponse(in);
      
    }
    
    public void pedidoProprioUsuario() {
        if (userToken == null) {
            log("Você precisa estar logado para fazer um pedido de dados do próprio usuário.");
            return;
        }

        Map<String, Object> request = createPedidoProprioUsuarioRequest(userToken);
        sendRequest(out, request);

        String response = processResponse(in);
   
    }
    
    public void excluirUsuario() {
        if (userToken == null) {
            log("Você precisa estar logado para excluir um usuário.");
            return;
        }

        String userId = showInputDialog("Digite o ID do usuário que deseja excluir:");

        Map<String, Object> request = createExcluirUsuarioRequest(userToken, userId);
        sendRequest(out, request);

        String response = processResponse(in);
    }
    
    public void listarUsuarios() {
        if (userToken == null) {
            log("Você precisa estar logado para listar os usuários.");
            return;
        }

        Map<String, Object> request = createListarUsuariosRequest(userToken);
        sendRequest(out, request);

        String response = processResponse(in);
    }

    public void sair() {
    	  System.exit(0);
    }
    
    

    private void sendRequest(PrintWriter out, Map<String, Object> request) {
        try {
            String jsonRequest = objectMapper.writeValueAsString(request);
            out.println(jsonRequest);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private String processResponse(BufferedReader in) {
        try {
            String jsonResponse = in.readLine();
            Map<String, Object> response = objectMapper.readValue(jsonResponse, Map.class);
            log("Resposta do servidor: " + response);
            showResponseAlert("Resposta do servidor:\n" + jsonResponse);

            if (response.containsKey("error")) {
                Object errorValue = response.get("error");

                if (errorValue instanceof Boolean && (Boolean) errorValue) {
                    String message = (String) response.get("message");
                    log("Erro: " + message);
                }
            }

            if (response.containsKey("data") && response.get("data") instanceof Map) {
                Map<String, Object> responseData = (Map<String, Object>) response.get("data");
                if (responseData.containsKey("token")) {
                    String token = (String) responseData.get("token");
                    log("Token recebido: " + token);
                    return token;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }
   
    ///////////////////////// ATENCAO /////////////////////////////////////
    //coloca uma mensagem para inserir o id nao esquece!!!  ///////////////
    ///////////////////////// ATENCAO /////////////////////////////////////
	private Map<String, Object> createAutoEdicaoUsuarioRequest(String token, String userId, String newName,
			String newEmail, String newPassword) {
		Map<String, Object> request = new HashMap<>();
		request.put("action", "autoedicao-usuario");
		Map<String, Object> data = new HashMap<>();
		data.put("token", token);
		data.put("name", newName);
		data.put("email", newEmail);
		data.put("id", userId);

		// data.put("type", "user");
		// createAutoEdicaoUsuarioRequest(userToken,userId, newName, newEmail,
		// newPassword);
		request.put("data", data);
		log("Pedido de autoedição de usuário enviado com sucesso. Token: " + token);
		return request;
	}

    private Map<String, Object> createExcluirUsuarioRequest(String token, String userId) {
        Map<String, Object> request = new HashMap<>();
        request.put("action", "excluir-usuario");
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("user_id", userId);
        request.put("data", data);
        log("Pedido de exclusão de usuário enviado com sucesso. Token: " + token + " / ID do Usuário: " + userId);
        return request;
    }

    private Map<String, Object> createCadastroUsuarioRequest(String token, String nome, String email, String senha, String tipo) {
        Map<String, Object> request = new HashMap<>();
        request.put("action", "cadastro-usuario");
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("name", nome);
        data.put("email", email);
        data.put("password", passwordMD5(senha));
        data.put("type", tipo);
        request.put("data", data);
        log("Mensagem enviada : Token: " + token + " / Nome: " + nome + " / Email: " + email + " / Senha: " + passwordMD5(senha) + " / ");
        return request;
    }
    
    private Map<String, Object> createCadastroUsuario1Request(String token, String nome, String email, String senha, String tipo) {
        Map<String, Object> request = new HashMap<>();
        request.put("action", "cadastro-usuario");
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("name", nome);
        data.put("email", email);
        data.put("password", passwordMD5(senha));
        data.put("type", tipo);
        request.put("data", data);
        log("Mensagem enviada : Token: " + token + " / Nome: " + nome + " / Email: " + email + " / Senha: " + passwordMD5(senha) + " / ");
        return request;
    }
    
    private Map<String, Object> createExcluirProprioUsuarioRequest(String token, String email, String senha) {
        Map<String, Object> request = new HashMap<>();
        request.put("action", "excluir-proprio-usuario");
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("email", email);
        data.put("password", passwordMD5(senha));
        request.put("data", data);
        log("Pedido para excluir o próprio usuário enviado com sucesso. Token: " + token + " / Email: " + email + " / Senha: " + passwordMD5(senha));
        return request;
    }
    
    private Map<String, Object> createAlterarDadosUsuarioRequest(String token, String userId, String newName, String newEmail, String newPassword, String newType) {
        Map<String, Object> request = new HashMap<>();
        request.put("action", "edicao-usuario");
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("user_id", userId);
        data.put("name", newName);
        data.put("email", newEmail);

        if (!newPassword.isEmpty()) {
            data.put("password", passwordMD5(newPassword));
        } else {
            data.put("password", null);
        }

        data.put("type", newType);
        request.put("data", data);
        log("Pedido de alteração de dados do usuário enviado com sucesso. Token: " + token + " / ID do Usuário: " + userId);
        return request;
    }

    private Map<String, Object> createLoginRequest(String email, String senha) {
        Map<String, Object> request = new HashMap<>();
        request.put("action", "login");
        Map<String, Object> data = new HashMap<>();
        data.put("email", email);
        data.put("password", passwordMD5(senha));
        request.put("data", data);
        log("Mensagem enviada : Email: " + email + " / Senha: " + passwordMD5(senha) + " / ");
        return request;
    }

    private Map<String, Object> createLogoutRequest(String token) {
        Map<String, Object> request = new HashMap<>();
        request.put("action", "logout");
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        request.put("data", data);
        return request;
    }

    private Map<String, Object> createCadastroUsuarioComumRequest(String nome, String email, String senha) {
        Map<String, Object> request = new HashMap<>();
        request.put("action", "autocadastro-usuario");
        Map<String, Object> data = new HashMap<>();
        data.put("name", nome);
        data.put("email", email);
        data.put("password", passwordMD5(senha));
        request.put("data", data);
        log("Mensagem enviada : Nome: " + nome + "Email: " + email + " / Senha: " + passwordMD5(senha) + " / ");
        return request;
    }
    private Map<String, Object> createPedidoEdicaoUsuarioRequest(String token, String userId) {
        Map<String, Object> request = new HashMap<>();
        request.put("action", "pedido-edicao-usuario");
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        data.put("user_id", userId);
        request.put("data", data);
        log("Mensagem enviada : Token: " + token + " / ID do Usuário: " + userId);
        return request;
    }
    
    private Map<String, Object> createPedidoProprioUsuarioRequest(String token) {
        Map<String, Object> request = new HashMap<>();
        request.put("action", "pedido-proprio-usuario");
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        request.put("data", data);
        log("Pedido de dados do próprio usuário enviado com sucesso. Token: " + token);
        return request;
    }
    
    private Map<String, Object> createListarUsuariosRequest(String token) {
        Map<String, Object> request = new HashMap<>();
        request.put("action", "listar-usuarios");
        Map<String, Object> data = new HashMap<>();
        data.put("token", token);
        request.put("data", data);
        log("Pedido de listagem de usuários enviado com sucesso. Token: " + token);
        return request;
    }

    private String showInputDialog(String message) {
        return JOptionPane.showInputDialog(frame, message);
    }

    private void log(String message) {
        logTextArea.append(message + "\n");
    }

    public static String passwordMD5(String password) {
        return DigestUtils.md5Hex(password).toUpperCase();
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new ClienteFinal();
            }
        });
    }
}