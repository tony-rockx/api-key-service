const request = require('supertest');
const app = require('../index');

const expect = require('chai').expect;

describe('API Key Endpoint test', function() {
    it('Test api key generation limit', function(done) {
        request(app)
        .post('/account')
        .send({
            user: 'xiaomeng',
            email: 'xiaomeng@rockx.com'
        })
        .expect(200)
        .end((err, res) => {
            if(err) {
                return done(err);
            }
            let response = res["body"];
            console.log(response);
            console.log(response["message"]);
            return done();
        })
    })
})