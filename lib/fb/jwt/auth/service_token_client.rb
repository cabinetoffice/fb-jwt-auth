require 'net/http'
require 'json'
require 'base64'

class Fb::Jwt::Auth::ServiceTokenClient
  class ServiceTokenCacheError < StandardError; end

  ENDPOINTS = {
    v2: '/service/v2/%{application}',
    v3: '/v3/applications/%{application}/namespaces/%{namespace}'
  }

  attr_accessor :application, :namespace, :root_url, :api_version

  def initialize(application:, namespace: nil, ignore_cache: false)
    @application = application
    @namespace = namespace
    @ignore_cache = ignore_cache
    @root_url = Fb::Jwt::Auth.service_token_cache_root_url
    @api_version = Fb::Jwt::Auth.service_token_cache_api_version || :v2
  end

  def public_key
    response = Net::HTTP.get_response(public_key_uri)

    unless response.code.to_i == 200
      raise ServiceTokenCacheError.new(
              "Unexpected response code\n" \
              "Response code: #{response.code} => Response body: #{response.body},
response.to_s: #{response.to_s}"
            )
    end

    Base64.strict_decode64(JSON.parse(response.body).fetch('token'))
  rescue Errno::ECONNREFUSED => e
    raise ServiceTokenCacheError.new(
      "Unable to connect to the Service Token Cache\n#{e.message}"
    )
  end

  private

  attr_reader :ignore_cache

  def public_key_uri
    logger = Logger.new(STDOUT)
    logger.info "public_key_uri: #{version_url}#{query_param}"
    URI.join(root_url, "#{version_url}#{query_param}")
  end

  def query_param
    ignore_cache ? '?ignore_cache=true' : ''
  end

  def version_url
    if api_version == :v3
      ENDPOINTS[api_version] % { application: application, namespace: namespace }
    else
      ENDPOINTS[api_version] % { application: application }
    end
  end
end
