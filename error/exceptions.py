class Error(Exception):
    """"""
    pass


class ResponseError(Error):
    """Exception raised for errors in response.

        Attributes:
              code -- response code that was returned.
              message -- explanation of the response code as per the Cylance API documentation.
        """

    def __init__(self, code):
        self.code = code
        self.message = str(self.code) + ' -- Unknown -- Unknown HTTP Code in response to this request.'


class Response400Error(Error):
    """Exception raised for errors in response.

    Attributes:
          code -- response code that was returned.
          message -- explanation of the response code as per the Cylance API documentation.
    """

    def __init__(self):

        self.code = 400
        self.message = str(self.code) + ' -- BadRequest -- Returned for the following reasons: The Tenant ID could ' \
                                        'not be retrieved, or The Threat Hash ID specified is invalid.'


class Response401Error(Error):
    """Exception raised for errors in response.

    Attributes:
          code -- response code that was returned.
          message -- explanation of the response code as per the Cylance API documentation.
    """

    def __init__(self):

        self.code = 401
        self.message = str(self.code) + ' -- Unauthorized -- The JWT token was not specified, has expired, or ' \
                                        'otherwise invalid.'


class Response403Error(Error):
    """Exception raised for errors in response.

    Attributes:
          code -- response code that was returned.
          message -- explanation of the response code as per the Cylance API documentation.
    """

    def __init__(self):

        self.code = 403
        self.message = str(self.code) + ' -- Forbidden -- The JWT token did not contain the proper scope to ' \
                                        'perform this action.'


class Response404Error(Error):
    """Exception raised for errors in response.

    Attributes:
          code -- response code that was returned.
          message -- explanation of the response code as per the Cylance API documentation.
    """

    def __init__(self):

        self.code = 404
        self.message = str(self.code) + ' -- NotFound -- The threat requested doesn\'t exist.'


class Response409Error(Error):
    """Exception raised for errors in response.

    Attributes:
          code -- response code that was returned.
          message -- explanation of the response code as per the Cylance API documentation.
    """

    def __init__(self):

        self.code = 409
        self.message = str(self.code) + ' -- Conflict -- This request conflicts with an aspect of another resource.' \
                                        'Can occur if tenant name or email are already in use.'


class Response500Error(Error):
    """Exception raised for errors in response.

    Attributes:
          code -- response code that was returned.
          message -- explanation of the response code as per the Cylance API documentation.
    """

    def __init__(self):

        self.code = 500
        self.message = str(self.code) + ' -- InternalServerError -- An unforeseeable error has occurred.'


class Response501Error(Error):
    """Exception raised for errors in response.

    Attributes:
          code -- response code that was returned.
          message -- explanation of the response code as per the Cylance API documentation.
    """

    def __init__(self):

        self.code = 501
        self.message = str(self.code) + ' -- Not Implemented -- A request was made against a resource has not not ' \
                                        'been implemented.'


class InvalidSHA256Error(Error):
    """Exception raised for errors in response.

    Attributes:
          code -- response code that was returned.
          message -- explanation of the response code as per the Cylance API documentation.
    """

    def __init__(self):

        self.message = 'Invalid SHA256 -- This hash does not meet the length requirements for SHA256'
