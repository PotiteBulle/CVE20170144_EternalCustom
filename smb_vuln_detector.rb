require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Advanced SMB Vulnerability Detector',
      'Description'    => %q{
        Detects if a target is running SMBv1 and evaluates specific SMB versions
        and configurations to identify potential vulnerabilities, including EternalBlue (MS17-010).
        Includes enhanced alerting and reporting capabilities.
      },
      'Author'         => ['Potate'], # Auteur du script
      'License'        => MSF_LICENSE,
      'References'     => [
        ['CVE', '2017-0144'],
        ['URL', 'https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010']
      ]
    ))

    # Options disponibles dans le module Metasploit
    register_options(
      [
        Opt::RPORT(445), # Port SMB par défaut
        OptString.new('RHOST', [true, 'The target IP address']), # Adresse IP cible
        OptBool.new('ENABLE_LOGGING', [false, 'Enable detailed logging', true]), # Option pour les logs détaillés
        OptString.new('ALERT_EMAIL', [false, 'Email address for sending alerts']) # Email pour les alertes
      ]
    )
  end

  def run
    print_status("Connecting to #{datastore['RHOST']}:#{datastore['RPORT']}...")
    connect # Établit une connexion au serveur cible

    # Envoi de la requête SMB handshake
    smb_request = generate_smb_handshake
    sock.put(smb_request) # Envoi via le socket
    print_status("Sent SMB handshake request.")

    # Réception et analyse de la réponse
    response = sock.get_once
    if response.nil?
      print_error("No response from target.")
      return
    end

    if smb_v1_detected?(response)
      print_good("Target supports SMBv1. Potential vulnerability detected.")
      log_vulnerability("SMBv1 detected on target.")

      if specific_version_detected?(response)
        print_good("Specific SMB version detected: Possible EternalBlue vulnerability.")
        log_vulnerability("EternalBlue-specific SMB version detected.")
      end

      alert_message = "SMBv1 detected on #{datastore['RHOST']}"
      trigger_alert(alert_message)
    else
      print_status("SMBv2/3 detected. Target is not vulnerable to SMBv1 exploits.")
    end

    detect_additional_features(response)
    disconnect # Ferme la connexion
  rescue ::Rex::ConnectionError
    print_error("Connection failed.")
  end

  def generate_smb_handshake
    # Génère une requête de handshake SMB basique
    [
      0x00, 0x00, 0x00, 0x85,
      0xfe, 0x53, 0x4d, 0x42,
      0x40, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00
    ].pack('C*')
  end

  def smb_v1_detected?(response)
    # Analyse la réponse pour détecter si SMBv1 est activé
    response[4..7] == "\xFFSMB"
  end

  def specific_version_detected?(response)
    # Analyse avancée pour détecter une version spécifique de SMB
    response.include?("Windows 7") || response.include?("Windows Server 2008 R2")
  end

  def detect_additional_features(response)
    # Détecte d'autres caractéristiques ou configurations de SMB
    if response.include?("SMB Signing Disabled")
      print_warning("SMB signing is disabled on the target. This is a security risk.")
      log_vulnerability("SMB signing disabled on target.")
    end

    if response.include?("Guest Account Enabled")
      print_warning("Guest account is enabled on the target. This may allow unauthorized access.")
      log_vulnerability("Guest account enabled on target.")
    end
  end

  def log_vulnerability(message)
    # Enregistre les vulnérabilités détectées dans Metasploit
    if datastore['ENABLE_LOGGING']
      report_vuln(
        host: datastore['RHOST'],
        port: datastore['RPORT'],
        name: 'SMB Vulnerability Detected',
        info: message
      )
      print_status("Logged vulnerability: #{message}")
    end
  end

  def trigger_alert(message)
    # Envoie une alerte automatisée
    print_warning("ALERT: #{message}")
    if datastore['ALERT_EMAIL']
      send_email_alert(message)
    end
  end

  def send_email_alert(message)
    # Placeholder pour l'envoi d'un email
    print_status("Sending alert email to #{datastore['ALERT_EMAIL']}: #{message}")
    # Implémentation spécifique à ajouter pour envoyer des emails
  end
end