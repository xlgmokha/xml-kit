require 'rspec/expectations'

RSpec::Matchers.define :match_xsd do |expected|
  match do |actual|
    file = File.expand_path(File.join(__dir__, "../../fixtures/xsd/#{expected}.xsd"))
    xml = Nokogiri::XML(actual).document
    Dir.chdir(File.dirname(file)) do
      xsd = Nokogiri::XML::Schema(IO.read(file))
      errors = xsd.validate(xml)
      @actual = errors
      expect(errors).to be_empty
    end
  end

  diffable
end

