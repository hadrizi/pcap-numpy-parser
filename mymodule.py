import numpy

def array_tutorial(a):
        print("array_tutorial - python")
        print(a)
        print(numpy.dtype(a[0]))
        print("")
        firstRow = a[0]

#        beta = numpy.array([[1,'123',3],[1,'tcp',3],[1,'yt',3]],dtype=numpy.float128)
#        print("myfunction - python")
#        print(beta)

        return firstRow

def myfunction():
        beta = numpy.array([[1,2,3],[1,2,3],[1,2,3]],dtype=numpy.float128)
        print("myfunction - python")
        print(beta)
        print("")
        firstRow = beta[0,:]
        return firstRow