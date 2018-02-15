module Xml
  module Kit
    # {include:file:spec/xml/certificate_spec.rb}
    class Certificate
      BASE64_FORMAT = %r(\A([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z)
      BEGIN_CERT=/-----BEGIN CERTIFICATE-----/
      END_CERT=/-----END CERTIFICATE-----/
      # The use can be `:signing` or `:encryption`. Use `nil` for both.
      attr_reader :use

      # The raw certificate value. This can be a Base64 encoded PEM or just a PEM format.
      attr_reader :value

      def initialize(value, use: nil)
        @value = value
        @use = use.nil? ? use : use.downcase.to_sym
      end

      # @return [Xml::Kit::Fingerprint] the certificate fingerprint.
      def fingerprint
        Fingerprint.new(value)
      end

      # Returns true if this certificate is for the specified use.
      #
      # @param use [Symbol] `:signing` or `:encryption`.
      # @return [Boolean] true or false.
      def for?(use)
        return true if self.use.nil?
        self.use == use.to_sym
      end

      # Returns true if this certificate is used for encryption.
      #
      # return [Boolean] true or false.
      def encryption?
        for?(:encryption)
      end

      # Returns true if this certificate is used for signing.
      #
      # return [Boolean] true or false.
      def signing?
        for?(:signing)
      end

      # Returns the x509 form.
      #
      # return [OpenSSL::X509::Certificate] the OpenSSL equivalent.
      def x509
        @x509 ||= self.class.to_x509(value)
      end

      # Returns the public key.
      #
      # @return [OpenSSL::PKey::RSA] the RSA public key.
      def public_key
        x509.public_key
      end

      def ==(other)
        self.fingerprint == other.fingerprint
      end

      def eql?(other)
        self == other
      end

      def hash
        value.hash
      end

      def to_s
        value
      end

      def to_h
        { use: @use, fingerprint: fingerprint.to_s }
      end

      def inspect
        to_h.inspect
      end

      def stripped
        self.class.strip(x509.to_pem)
      end

      def to_key_pair(private_key, passphrase: nil, use: nil)
        KeyPair.new(x509.to_pem, private_key.to_s, passphrase, use)
      end

      def expired?(time = Time.now)
        x509.not_after <= time
      end

      def active?(time)
        x509.not_before <= time && x509.not_after > time
      end

      class << self
        def to_x509(value)
          return value if value.is_a?(OpenSSL::X509::Certificate)

          value = Base64.decode64(strip(value)) if base64?(value)
          OpenSSL::X509::Certificate.new(value)
        end

        def base64?(value)
          return unless value.is_a?(String)

          sanitized_value = strip(value)
          !!sanitized_value.match(BASE64_FORMAT)
        end

        def strip(value)
          value.
            gsub(BEGIN_CERT, '').
            gsub(END_CERT, '').
            gsub(/[\r\n]|\\r|\\n|\s/, "")
        end
      end
    end
  end
end
