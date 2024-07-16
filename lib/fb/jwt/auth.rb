require 'fb/jwt/auth/version'
require 'openssl'
require 'jwt'
require 'active_support/all'

module Fb
  module Jwt
    class Auth
      cattr_accessor :service_token_cache_root_url,
                     :service_token_cache_api_version,
                     :encoded_private_key,
                     :issuer,
                     :namespace

      def self.configure(&block)
        yield self
      end

      autoload :ServiceTokenClient, 'fb/jwt/auth/service_token_client'
      autoload :ServiceAccessToken, 'fb/jwt/auth/service_access_token'

      class TokenNotPresentError < StandardError
      end

      class TokenNotValidError < StandardError
      end

      class TokenExpiredError < StandardError
      end

      class IssuerNotPresentError < StandardError
      end

      class NamespaceNotPresentError < StandardError
      end

      attr_accessor :token, :key, :leeway, :logger

      def initialize(token:, key: nil, leeway:, logger:)
        @token = token
        @key = key
        @leeway = leeway
        @logger = logger
      end

      def verify!
        raise TokenNotPresentError.new('Token is not present') if token.blank?

        application_details = find_application_info

        @logger.info "=====> verify!, application_details: #{application_details}"

        begin
          payload, _header = retrieve_and_decode_public_key(application_details)
        rescue StandardError => e
          error_message = "Token is not valid: error #{e}"
          logger.debug(error_message)
          raise TokenNotValidError.new(error_message)
        end

        # NOTE: verify_iat used to be in the JWT gem, but was removed in v2.2
        # so we have to do it manually
        iat_skew = payload['iat'].to_i - Time.zone.now.to_i

        if iat_skew.abs > leeway.to_i
          error_message = "Token has expired: iat skew is #{iat_skew}, max is #{leeway}"
          logger.debug(error_message)

          raise TokenExpiredError.new(error_message)
        end

        logger.debug 'token is valid'
        payload
      end

      def retrieve_and_decode_public_key(application_details)
        @logger.info "====> retrieve_and_decode_public_key: #{application_details}"
        hmac_secret = public_key(application_details)
        decode(hmac_secret: hmac_secret)
      rescue JWT::VerificationError
        logger.debug('First validation failed. Requesting non cached public key')
        hmac_secret = public_key(application_details.merge(ignore_cache: true))
        decode(hmac_secret: hmac_secret)
      end

      def decode(verify: true, hmac_secret: nil)
        JWT.decode(
          token,
          hmac_secret,
          verify,
          exp_leeway: leeway,
          algorithm: 'RS256'
        )
      end

      def find_application_info
        return { application: key } if key

        payload, _header = decode(verify: false)
        application = payload['iss']
        namespace = payload['namespace']

        raise IssuerNotPresentError.new('Issuer is not present in the token') unless application
        raise NamespaceNotPresentError.new('Namespace is not present in the token') unless namespace

        { application: application, namespace: namespace}
      end

      def public_key(attributes)
        OpenSSL::PKey::RSA.new(
          ServiceTokenClient.new(**attributes).public_key
        )
      end
    end
  end
end
