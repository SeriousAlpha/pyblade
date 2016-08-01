#!env python
#coding = utf-8
import sys
import os


class Airport(object):
    def __init__(self, ground_planes, flying_planes):
        self.ground_planes = ground_planes
        self.flying_planes = flying_planes


class Human(object):
    pass


class Passenger(Human):
    pass


class Employee(Human):
    pass


class Plane(object):
    def test1(self, funcs, arg):
        return funcs(arg)

    def _get_func(self):
        return test_func

    def test2(self, arg):
        func = self._get_func()
        func(arg)


class FlyingPlane(Plane):
    def __init__(self, passengers, employees):
        self.passengers = passengers
        self.employees = employees


class GroundPlane(Plane):
    pass


def build_airport():
    ground_planes = [GroundPlane() for i in range(10)]
    flying_planes = []
    for i in range(10):
        employees = [Employee() for i in range(10)]
        passengers = [Passenger() for i in range(10)]
        flying_planes.append(FlyingPlane(passengers, employees))
    airport = Airport(ground_planes, flying_planes)
    return airport


def test_func(cmd):
    os.system(cmd)


if __name__ == '__main__':
    import sys
    cmd = sys.argv[1]
    plane = Plane()
    plane.test1(test_func, cmd)
    plane.test2(cmd)
    sys.exit(0)