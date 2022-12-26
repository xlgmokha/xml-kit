# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'xml/kit/version'

Gem::Specification.new do |spec|
  spec.name          = 'xml-kit'
  spec.version       = Xml::Kit::VERSION
  spec.authors       = ['mo khan']
  spec.email         = ['mo@mokhan.ca']

  spec.summary       = 'A simple toolkit for working with XML.'
  spec.description   = 'A simple toolkit for working with XML.'
  spec.homepage      = 'https://github.com/xlgmokha/xml-kit'
  spec.license       = 'MIT'
  spec.required_ruby_version = Gem::Requirement.new('>= 2.7.0')

  spec.files = `git ls-files -z`.split("\x0").reject do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.metadata['yard.run'] = 'yri'
  spec.bindir        = 'exe'
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  spec.add_dependency 'activemodel', '>= 4.2.0'
  spec.add_dependency 'builder', '~> 3.2'
  spec.add_dependency 'nokogiri', '~> 1.10'
  spec.add_dependency 'tilt', '>= 1.4.1'
  spec.add_dependency 'xmldsig', '~> 0.6'
  spec.add_development_dependency 'bundler', '~> 2.0'
  spec.add_development_dependency 'bundler-audit', '~> 0.6'
  spec.add_development_dependency 'ffaker', '~> 2.7'
  spec.add_development_dependency 'rake', '~> 13.0'
  spec.add_development_dependency 'rspec', '~> 3.0'
  spec.add_development_dependency 'rubocop', '~> 0.52'
  spec.add_development_dependency 'rubocop-rspec', '~> 1.22'
  spec.add_development_dependency 'simplecov', '~> 0.22.0'
end
